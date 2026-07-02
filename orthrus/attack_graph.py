"""Reachability attack graph — collapse a flat finding list into the few attack
*paths* an adversary can actually walk.

``chains.py`` matches findings against a rule catalog and emits each matched rule
independently. This engine goes further: it treats the same rule catalog as a set
of directed *enables* edges between findings, builds a per-host graph, and
extracts the **maximal** kill-chains. Because edges compose, two rules that share
a finding merge into one longer path — e.g. `LFI → exposed-secret` (rule A) and
`exposed-secret → auth-forgery` (rule B) collapse into a single three-step path
`LFI → secret → auth-forgery` that neither rule expresses alone.

The output is the handful of reachable attack paths, each with its combined
severity and impact narrative, plus the **collapse ratio** — how many raw
findings lie on a reachable path (Trident-style "N findings → M paths"). Pure and
deterministic: ``build_attack_graph`` takes findings and returns the report.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from orthrus.chains import CHAIN_RULES

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_MAX_PATHS_PER_HOST = 200  # safety cap against pathological fan-out
_MAX_DEPTH = 12


def _vt(finding: object) -> str:
    return getattr(finding, "vuln_type", "") or ""


def _sev(finding: object) -> str:
    sev = getattr(finding, "severity", "")
    return getattr(sev, "value", sev) or "info"  # accept enum or str


def _host_of(url: str) -> str:
    return (urlsplit(url or "").hostname or "").lower()


@dataclass
class GraphStep:
    vuln_type: str
    url: str
    severity: str


@dataclass
class AttackPath:
    """A maximal entry→impact walk through the finding graph on one host."""

    host: str
    severity: str  # combined (max rule severity along the path)
    impact: str  # narrative of the terminal escalation
    via: list[str]  # rule names traversed, in order
    steps: list[GraphStep] = field(default_factory=list)

    @property
    def length(self) -> int:
        return len(self.steps)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "severity": self.severity,
            "length": self.length,
            "impact": self.impact,
            "via": self.via,
            "steps": [
                {"vuln_type": s.vuln_type, "url": s.url, "severity": s.severity} for s in self.steps
            ],
        }


def _host_edges(findings: list) -> tuple[dict, dict, set, dict]:
    """Build the enables-graph for one host's findings.

    Returns (edges, impacts, entries, node_by_id) where:
      * edges: src find-id -> list[(dst find-id, rule_name, rule_severity)]
      * impacts: terminal find-id -> list[(rule_name, rule_severity, impact_text)]
      * entries: find-ids that are the first step of some matched rule
      * node_by_id: find-id -> finding
    """
    node_by_id: dict[int, object] = {id(f): f for f in findings}
    by_vt: dict[str, list] = defaultdict(list)
    for f in findings:
        by_vt[_vt(f)].append(f)

    edges: dict[int, list] = defaultdict(list)
    impacts: dict[int, list] = defaultdict(list)
    entries: set[int] = set()

    for rule in CHAIN_RULES:
        # Satisfy each link with a *distinct* finding, matching chains.py semantics.
        chosen: list[object] = []
        used: set[int] = set()
        ok = True
        for link in rule.links:
            cand = next(
                (
                    f
                    for vt in link.vuln_types
                    for f in by_vt.get(vt, [])
                    if id(f) not in used
                ),
                None,
            )
            if cand is None:
                ok = False
                break
            used.add(id(cand))
            chosen.append(cand)
        if not ok:
            continue

        entries.add(id(chosen[0]))
        for a, b in zip(chosen, chosen[1:], strict=False):
            edges[id(a)].append((id(b), rule.name, rule.severity))
        impacts[id(chosen[-1])].append((rule.name, rule.severity, rule.impact))

    return edges, impacts, entries, node_by_id


def _extract_paths(edges: dict, impacts: dict, entries: set) -> list[list[int]]:
    """All maximal simple paths from an entry to an impact-bearing node."""
    incoming: set[int] = {dst for outs in edges.values() for dst, _n, _s in outs}
    starts = [e for e in entries if e not in incoming] or list(entries)

    recorded: list[list[int]] = []
    for start in sorted(starts):
        stack: list[tuple[int, tuple[int, ...]]] = [(start, (start,))]
        while stack and len(recorded) < _MAX_PATHS_PER_HOST:
            node, path = stack.pop()
            if node in impacts:
                recorded.append(list(path))
            if len(path) >= _MAX_DEPTH:
                continue
            for dst, _name, _sev in edges.get(node, []):
                if dst not in path:  # simple-path (cycle guard)
                    stack.append((dst, (*path, dst)))

    # Keep only maximal paths: drop any that is a strict prefix of a longer one.
    recorded.sort(key=len, reverse=True)
    maximal: list[list[int]] = []
    for p in recorded:
        tp = tuple(p)
        if not any(tuple(m[: len(p)]) == tp and len(m) > len(p) for m in maximal):
            maximal.append(p)
    return maximal


def _path_severity(path: list[int], edges: dict, impacts: dict) -> tuple[str, str]:
    """Combined severity (max rule severity along the path) + terminal impact text."""
    sev_rank = 0
    for node in path:
        for _dst, _name, s in edges.get(node, []):
            sev_rank = max(sev_rank, _SEV_ORDER.get(s, 0))
        for _name, s, _impact in impacts.get(node, []):
            sev_rank = max(sev_rank, _SEV_ORDER.get(s, 0))
    severity = next((k for k, v in _SEV_ORDER.items() if v == sev_rank), "info")
    terminal = impacts.get(path[-1], [])
    # Prefer the highest-severity impact narrative at the terminal node.
    terminal_sorted = sorted(terminal, key=lambda t: -_SEV_ORDER.get(t[1], 0))
    impact_text = terminal_sorted[0][2] if terminal_sorted else ""
    return severity, impact_text


def _path_via(path: list[int], edges: dict, impacts: dict) -> list[str]:
    via: list[str] = []
    for a, b in zip(path, path[1:], strict=False):
        name = next((n for dst, n, _s in edges.get(a, []) if dst == b), None)
        if name:
            via.append(name)
    if not via and path and impacts.get(path[-1]):
        via.append(impacts[path[-1]][0][0])
    return via


def correlate_paths(findings: list) -> list[AttackPath]:
    """Return the maximal attack paths present in ``findings``, worst-first."""
    by_host: dict[str, list] = defaultdict(list)
    for f in findings:
        by_host[_host_of(getattr(f, "url", ""))].append(f)

    paths: list[AttackPath] = []
    for host, host_findings in by_host.items():
        edges, impacts, entries, node_by_id = _host_edges(host_findings)
        for node_path in _extract_paths(edges, impacts, entries):
            severity, impact = _path_severity(node_path, edges, impacts)
            steps = [
                GraphStep(_vt(node_by_id[nid]), getattr(node_by_id[nid], "url", ""), _sev(node_by_id[nid]))
                for nid in node_path
            ]
            paths.append(
                AttackPath(
                    host=host,
                    severity=severity,
                    impact=impact,
                    via=_path_via(node_path, edges, impacts),
                    steps=steps,
                )
            )

    paths.sort(key=lambda p: (-_SEV_ORDER.get(p.severity, 0), -p.length, p.host))
    return paths


@dataclass
class AttackGraphReport:
    paths: list[AttackPath]
    total_findings: int

    @property
    def reachable_findings(self) -> int:
        """Distinct findings that lie on at least one attack path (by url+vuln_type)."""
        keys = {(s.vuln_type, s.url) for p in self.paths for s in p.steps}
        return len(keys)

    def summary(self) -> str:
        if not self.paths:
            return f"no attack paths correlated ({self.total_findings} findings)"
        crit = sum(1 for p in self.paths if p.severity == "critical")
        return (
            f"{self.total_findings} findings collapsed into {len(self.paths)} attack path(s) "
            f"({crit} critical); {self.reachable_findings} finding(s) on a reachable path"
        )

    def to_dict(self) -> dict:
        return {
            "summary": self.summary(),
            "total_findings": self.total_findings,
            "reachable_findings": self.reachable_findings,
            "path_count": len(self.paths),
            "paths": [p.to_dict() for p in self.paths],
        }


def build_attack_graph(findings: list) -> AttackGraphReport:
    return AttackGraphReport(correlate_paths(findings), total_findings=len(findings))


__all__ = [
    "GraphStep",
    "AttackPath",
    "AttackGraphReport",
    "correlate_paths",
    "build_attack_graph",
]
