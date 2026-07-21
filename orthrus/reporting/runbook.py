"""Consolidated remediation runbook - collapse a flat finding list into the few
*fixes* that actually retire the risk, ordered so the highest-leverage change is
first.

A scan report lists findings; a runbook lists **actions**. Findings that share a
remediation (same ``vuln_type``) become one fix action spanning every affected
endpoint, so "42 SQLi findings across 9 URLs" reads as a single "parameterise
queries" task. Actions are then ranked by leverage: a fix that removes a step
from a correlated attack path (see ``attack_graph``) sorts above an equally-severe
fix that only clears isolated findings - breaking one link collapses the whole
kill-chain.

Pure and deterministic: ``build_runbook`` takes findings and returns a ``Runbook``
that renders to Markdown. No I/O, no clock.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from orthrus.attack_graph import correlate_paths

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_MAX_URLS_SHOWN = 15  # keep an action's endpoint list readable; note the remainder


def _sev(finding: object) -> str:
    sev = getattr(finding, "severity", "")
    return getattr(sev, "value", sev) or "info"  # accept enum or str


def _vt(finding: object) -> str:
    return getattr(finding, "vuln_type", "") or "finding"


def _worst(severities: list[str]) -> str:
    rank = max((_SEV_ORDER.get(s, 0) for s in severities), default=0)
    return next((k for k, v in _SEV_ORDER.items() if v == rank), "info")


def _representative(values: list[str]) -> str:
    """Most common non-empty value, tie-broken toward the shortest (cleanest label)."""
    counts = Counter(v for v in values if v)
    if not counts:
        return ""
    top = max(counts.values())
    return min((v for v, c in counts.items() if c == top), key=len)


def _fullest(values: list[str]) -> str:
    """The longest non-empty value - the most complete remediation text in a group."""
    return max((v for v in values if v), key=len, default="")


@dataclass
class FixAction:
    """One remediation covering every finding that shares it."""

    vuln_type: str
    title: str
    severity: str
    count: int
    urls: list[str]
    cwe: str | None
    remediation: str
    breaks_paths: list[str] = field(default_factory=list)

    @property
    def on_attack_path(self) -> bool:
        return bool(self.breaks_paths)

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "title": self.title,
            "severity": self.severity,
            "count": self.count,
            "endpoints": len(self.urls),
            "urls": self.urls,
            "cwe": self.cwe,
            "remediation": self.remediation,
            "breaks_paths": self.breaks_paths,
        }


def _path_signatures(findings: list) -> list[tuple[str, set]]:
    """(human signature, {(vuln_type, url) on the path}) for each correlated path."""
    out: list[tuple[str, set]] = []
    for p in correlate_paths(findings):
        sig = " → ".join(s.vuln_type for s in p.steps)
        if p.impact:
            sig += f"  ⇒ {p.impact}"
        keys = {(s.vuln_type, s.url) for s in p.steps}
        out.append((sig, keys))
    return out


def _priority(action: FixAction) -> tuple:
    # attack-path fixes first, then severity, then blast radius (count), then stable.
    return (
        0 if action.on_attack_path else 1,
        -_SEV_ORDER.get(action.severity, 0),
        -action.count,
        action.vuln_type,
    )


@dataclass
class Runbook:
    actions: list[FixAction]
    total_findings: int
    target: str | None = None
    scan_id: str | None = None

    @property
    def path_breaking(self) -> int:
        return sum(1 for a in self.actions if a.on_attack_path)

    def summary(self) -> str:
        if not self.actions:
            return f"no remediable findings ({self.total_findings} findings)"
        line = (
            f"{self.total_findings} finding(s) collapse into {len(self.actions)} fix action(s)"
        )
        if self.path_breaking:
            line += f"; {self.path_breaking} break at least one attack path"
        return line

    def to_markdown(self) -> str:
        scope = self.target or self.scan_id or "scan"
        out: list[str] = [f"# Remediation Runbook - {scope}", "", f"_{self.summary()}._", ""]
        if not self.actions:
            out.append("No findings require remediation.")
            return "\n".join(out) + "\n"
        out += [
            "Work top-down: actions are ordered by leverage - fixes that break an "
            "attack path come first, then by severity and blast radius.",
            "",
        ]
        for i, a in enumerate(self.actions, 1):
            out.append(f"## {i}. {a.title} - {a.severity.upper()}")
            span = f"**Fixes {a.count} finding(s)** across {len(a.urls)} endpoint(s)."
            if a.cwe:
                span += f" · {a.cwe}"
            out.append(span)
            for sig in a.breaks_paths:
                out.append(f"> 🔓 Breaks attack path: {sig}")
            out += ["", f"**Remediation:** {a.remediation or '-'}", "", "**Affected endpoints:**"]
            out += [f"- `{u}`" for u in a.urls[:_MAX_URLS_SHOWN]]
            if len(a.urls) > _MAX_URLS_SHOWN:
                out.append(f"- …and {len(a.urls) - _MAX_URLS_SHOWN} more.")
            out.append("")
        return "\n".join(out) + "\n"

    def to_dict(self) -> dict:
        return {
            "summary": self.summary(),
            "total_findings": self.total_findings,
            "action_count": len(self.actions),
            "path_breaking": self.path_breaking,
            "actions": [a.to_dict() for a in self.actions],
        }


def build_runbook(
    findings: list, *, target: str | None = None, scan_id: str | None = None
) -> Runbook:
    """Group findings by shared fix, tag path-breakers, and order by leverage."""
    groups: dict[str, list] = {}
    for f in findings:
        groups.setdefault(_vt(f), []).append(f)

    sigs = _path_signatures(findings)
    actions: list[FixAction] = []
    for vt, group in groups.items():
        urls = sorted({getattr(f, "url", "") or "" for f in group})
        url_set = set(urls)
        breaks = sorted(
            {sig for sig, keys in sigs if any((vt, u) in keys for u in url_set)}
        )
        actions.append(
            FixAction(
                vuln_type=vt,
                title=_representative([getattr(f, "title", "") for f in group]) or vt,
                severity=_worst([_sev(f) for f in group]),
                count=len(group),
                urls=urls,
                cwe=next((getattr(f, "cwe", None) for f in group if getattr(f, "cwe", None)), None),
                remediation=_fullest([getattr(f, "remediation", "") or "" for f in group]),
                breaks_paths=breaks,
            )
        )

    actions.sort(key=_priority)
    return Runbook(actions, total_findings=len(findings), target=target, scan_id=scan_id)


__all__ = ["FixAction", "Runbook", "build_runbook"]
