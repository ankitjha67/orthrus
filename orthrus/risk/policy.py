"""Deterministic, auditable finding-policy engine (Glasswing S5 / lesson 4.5).

The whitepaper's requirement: "every suppression or promotion decision is traceable
to a specific policy... enabling auditability and repeatability of the filtering
logic." ORTHRUS already has per-program mute rules and a bounty triage heuristic;
this adds the missing piece - a set of **named, declarative** policies evaluated in
a fixed order, where each finding's keep / suppress / escalate verdict records
*which* policy decided it and *why*. Same finding + same policy set -> same verdict
+ same rationale, every time.

A policy with no match conditions matches **nothing** (you can never accidentally
suppress everything). Policies are plain data (``from_dict`` / ``as_dict``) so a
policy set can live in config and be reviewed like any other control.
"""

from __future__ import annotations

from dataclasses import dataclass

KEEP, SUPPRESS, ESCALATE = "keep", "suppress", "escalate"
_ACTIONS = frozenset({KEEP, SUPPRESS, ESCALATE})
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _sev_rank(value: object) -> int:
    return _SEV_RANK.get(getattr(value, "value", str(value)).lower(), 0)


def _conf(finding: object) -> str:
    value = getattr(finding, "confidence", "")
    return getattr(value, "value", str(value)).lower()


def _kev(finding: object) -> bool:
    return bool(getattr(finding, "kev", False) or getattr(finding, "known_exploited", False))


@dataclass(frozen=True)
class Policy:
    """One declarative rule. All *set* conditions must hold for it to match."""

    name: str
    action: str = KEEP
    priority: int = 100                       # lower evaluates first
    reason: str = ""
    vuln_types: tuple[str, ...] = ()
    confidences: tuple[str, ...] = ()
    severity_below: str | None = None         # matches findings strictly below this rank
    severity_at_least: str | None = None      # matches findings at or above this rank
    kev: bool | None = None                   # None = ignore
    host_contains: str = ""
    title_contains: str = ""

    def matches(self, finding: object) -> bool:
        conds: list[bool] = []
        if self.vuln_types:
            vt = (getattr(finding, "vuln_type", "") or "").lower()
            conds.append(vt in {v.lower() for v in self.vuln_types})
        if self.confidences:
            conds.append(_conf(finding) in {c.lower() for c in self.confidences})
        if self.severity_below is not None:
            conds.append(_sev_rank(getattr(finding, "severity", "info"))
                         < _SEV_RANK.get(self.severity_below.lower(), 0))
        if self.severity_at_least is not None:
            conds.append(_sev_rank(getattr(finding, "severity", "info"))
                         >= _SEV_RANK.get(self.severity_at_least.lower(), 0))
        if self.kev is not None:
            conds.append(_kev(finding) == self.kev)
        if self.host_contains:
            conds.append(self.host_contains.lower() in (getattr(finding, "url", "") or "").lower())
        if self.title_contains:
            conds.append(self.title_contains.lower() in (getattr(finding, "title", "") or "").lower())
        # No conditions -> matches nothing (never suppress everything by accident).
        return bool(conds) and all(conds)

    @classmethod
    def from_dict(cls, data: dict) -> Policy:
        action = str(data.get("action", KEEP)).lower()
        if action not in _ACTIONS:
            raise ValueError(f"policy action must be one of {sorted(_ACTIONS)}, got {action!r}")
        return cls(
            name=str(data["name"]),
            action=action,
            priority=int(data.get("priority", 100)),
            reason=str(data.get("reason", "")),
            vuln_types=tuple(data.get("vuln_types", ()) or ()),
            confidences=tuple(data.get("confidences", ()) or ()),
            severity_below=data.get("severity_below"),
            severity_at_least=data.get("severity_at_least"),
            kev=data.get("kev"),
            host_contains=str(data.get("host_contains", "")),
            title_contains=str(data.get("title_contains", "")),
        )


@dataclass(frozen=True)
class PolicyDecision:
    verdict: str          # keep | suppress | escalate
    policy: str           # name of the deciding policy, or "default"
    reason: str

    def as_dict(self) -> dict:
        return {"verdict": self.verdict, "policy": self.policy, "reason": self.reason}


def default_policies() -> list[Policy]:
    """A sensible, conservative starting policy set - order matters."""
    return [
        Policy("kev-escalate", ESCALATE, priority=10, kev=True,
               reason="known-exploited (CISA KEV) - always surfaced, never suppressed"),
        Policy("confirmed-keep", KEEP, priority=20, confidences=("confirmed",),
               reason="re-proven exploitable - always reported"),
        Policy("tentative-below-high", SUPPRESS, priority=50, confidences=("tentative",),
               severity_below="high",
               reason="tentative and below high severity - confirm before reporting"),
        Policy("severity-floor", SUPPRESS, priority=60, severity_below="low",
               reason="below the low-severity floor"),
    ]


def evaluate(finding: object, policies: list[Policy]) -> PolicyDecision:
    """First matching policy (by priority, then name) decides; else keep by default."""
    for p in sorted(policies, key=lambda p: (p.priority, p.name)):
        if p.matches(finding):
            return PolicyDecision(p.action, p.name, p.reason or f"matched policy {p.name}")
    return PolicyDecision(KEEP, "default", "no policy matched - kept by default")


def apply_policies(findings: list, policies: list[Policy]) -> dict[str, list[tuple]]:
    """Partition findings into keep/suppress/escalate, each item paired with its decision."""
    buckets: dict[str, list[tuple]] = {KEEP: [], SUPPRESS: [], ESCALATE: []}
    for finding in findings:
        decision = evaluate(finding, policies)
        buckets[decision.verdict].append((finding, decision))
    return buckets


__all__ = [
    "KEEP", "SUPPRESS", "ESCALATE",
    "Policy", "PolicyDecision",
    "default_policies", "evaluate", "apply_policies",
]
