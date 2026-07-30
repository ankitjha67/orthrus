"""Priority scoring for the bug queue (PRD §7.5).

A single 0-100 number so the reportable bugs sort like a work queue: severity is
the base, scaled by how *sure* we are (a **confirmed** medium can outrank a
**tentative** high - the confirmed one is submittable now), with a CVSS nudge.
Kept deterministic and dependency-free so it's testable and stable; EPSS/KEV/
reward-tier weighting from the PRD can layer on once those live on the finding.
"""

from __future__ import annotations

_SEV_WEIGHT = {"critical": 100.0, "high": 78.0, "medium": 55.0, "low": 30.0, "info": 12.0}
_CONF_MULT = {"confirmed": 1.0, "firm": 0.85, "tentative": 0.6}


def _sev(value: object) -> str:
    return getattr(value, "value", str(value)).lower()


def _conf(value: object) -> str:
    return getattr(value, "value", str(value)).lower()


def priority_score(finding) -> float:
    """Composite 0-100 priority: ``severity × confidence + CVSS nudge``."""
    base = _SEV_WEIGHT.get(_sev(finding.severity), 12.0)
    mult = _CONF_MULT.get(_conf(finding.confidence), 0.6)
    cvss = finding.cvss_score or 0.0  # 0-10, a small tie-breaking nudge
    return round(min(100.0, base * mult + cvss), 1)


def priority_band(finding, context=None) -> str:
    """Contextual P1-P4 band (Glasswing/VVAH S7): CVSS + KEV/EPSS + exposure +
    asset criticality + confirmed-exploitability, deterministic and auditable.

    See ``orthrus.risk.priority`` for the scoring and its rationale.
    """
    from orthrus.risk import assess_priority

    return assess_priority(finding, context).band


__all__ = ["priority_band", "priority_score"]
