"""Contextual, exploitability-first risk prioritisation into P1-P4 bands.

Implements the Glasswing/VVAH S7 idea in ORTHRUS's DAST world: normalise severity
with the context that actually decides real risk - proven exploitability
(confirmed re-proof), exploit availability (KEV / EPSS), internet exposure, asset
criticality, and compensating controls that break the kill chain - into a
deterministic priority band (P1 = act now ... P4 = deprioritised), each with an
auditable rationale.

The whitepaper's point drives the weighting: "fewer than 1% of CVEs are actively
exploited, so prioritization matters more than volume", and "keep decisions
deterministic and audit traceable" - the same evidence must always produce the
same band, and every band must explain itself.

Pure and dependency-free. KEV/EPSS are read defensively (``getattr``) so this
works whether or not that enrichment currently lives on the finding, exactly like
``bounty.triage.priority_score``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Severity anchor (0-100), tempered by how sure we are it is real. A confirmed
# medium can outrank a tentative high - that is the exploitability-first stance.
_SEV_BASE = {"critical": 100.0, "high": 78.0, "medium": 55.0, "low": 30.0, "info": 12.0}
_CONF_MULT = {"confirmed": 1.0, "firm": 0.9, "tentative": 0.75}

# Business-context deltas.
_ASSET_DELTA = {"critical": 12.0, "high": 6.0, "medium": 0.0, "low": -8.0}
_KEV_BOOST = 20.0          # known-exploited in the wild (CISA KEV)
_EPSS_MAX = 25.0           # EPSS 0..1 scaled to at most +25
_EXPOSURE_UP = 8.0         # internet-facing
_EXPOSURE_DOWN = -6.0      # internal-only

# Band thresholds on the 0-100 composite.
_P1, _P2, _P3 = 82.0, 58.0, 32.0

BAND_MEANING = {
    "P1": "Act now - exploitable and exposed; highest business risk.",
    "P2": "High - schedule promptly; strong risk signal.",
    "P3": "Medium - fix in the normal cycle.",
    "P4": "Low - deprioritised; hardening / accept-with-note.",
}


@dataclass(frozen=True)
class RiskContext:
    """Business context that sharpens a finding's real risk.

    All optional with conservative defaults (unknown -> higher priority): a
    bounty/DAST target is assumed internet-facing and of medium criticality, and
    no compensating control is assumed unless the operator states one.
    """

    asset_criticality: str = "medium"          # critical | high | medium | low
    internet_facing: bool = True
    compensating_controls: float = 0.0         # 0..30 kill-chain-break reduction


@dataclass(frozen=True)
class PriorityAssessment:
    band: str                                  # P1 | P2 | P3 | P4
    score: float                               # 0-100 composite
    rationale: list[str] = field(default_factory=list)

    @property
    def meaning(self) -> str:
        return BAND_MEANING.get(self.band, "")


def _enum_str(value: object) -> str:
    return getattr(value, "value", str(value)).lower()


def _epss_of(finding: object) -> float:
    raw = getattr(finding, "epss", None)
    try:
        return max(0.0, min(1.0, float(raw)))
    except (TypeError, ValueError):
        return 0.0


def _kev_of(finding: object) -> bool:
    return bool(getattr(finding, "kev", False) or getattr(finding, "known_exploited", False))


def _band_of(score: float) -> str:
    if score >= _P1:
        return "P1"
    if score >= _P2:
        return "P2"
    if score >= _P3:
        return "P3"
    return "P4"


def assess_priority(finding: object, context: RiskContext | None = None) -> PriorityAssessment:
    """Deterministically map a finding + context to a P1-P4 band with rationale."""
    ctx = context or RiskContext()
    sev = _enum_str(getattr(finding, "severity", "info"))
    conf = _enum_str(getattr(finding, "confidence", "tentative"))

    base = _SEV_BASE.get(sev, 12.0)
    mult = _CONF_MULT.get(conf, 0.75)
    score = base * mult
    rationale = [f"severity {sev} x confidence {conf} = {score:.1f}"]

    if _kev_of(finding):
        score += _KEV_BOOST
        rationale.append(f"CISA-KEV known-exploited +{_KEV_BOOST:.0f}")

    epss = _epss_of(finding)
    if epss > 0:
        delta = round(epss * _EPSS_MAX, 1)
        score += delta
        rationale.append(f"EPSS {epss:.2f} exploit-probability +{delta}")

    if ctx.internet_facing:
        score += _EXPOSURE_UP
        rationale.append(f"internet-facing +{_EXPOSURE_UP:.0f}")
    else:
        score += _EXPOSURE_DOWN
        rationale.append(f"internal-only {_EXPOSURE_DOWN:.0f}")

    ac = ctx.asset_criticality.lower()
    ac_delta = _ASSET_DELTA.get(ac, 0.0)
    if ac_delta:
        rationale.append(f"asset criticality {ac} {ac_delta:+.0f}")
        score += ac_delta

    cc = max(0.0, float(ctx.compensating_controls or 0.0))
    if cc:
        score -= cc
        rationale.append(f"compensating controls (kill-chain break) -{cc:.0f}")

    score = round(max(0.0, min(100.0, score)), 1)
    band = _band_of(score)
    rationale.append(f"= {score:.1f} -> {band}")
    return PriorityAssessment(band=band, score=score, rationale=rationale)


def priority_band(finding: object, context: RiskContext | None = None) -> str:
    """Convenience: just the P1-P4 band."""
    return assess_priority(finding, context).band


__all__ = [
    "RiskContext",
    "PriorityAssessment",
    "BAND_MEANING",
    "assess_priority",
    "priority_band",
]
