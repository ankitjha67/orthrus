"""Slither adapter — normalize the Solidity static analyzer's JSON (PRD Phase 5, web3).

Slither is the standard smart-contract static analyzer. This maps each detector
result to an ORTHRUS Finding — impact→severity, confidence→confidence — carrying
the contract file/line as evidence, so web3 findings flow through the same
graph/triage/report pipeline as web findings.
"""

from __future__ import annotations

import json

from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.integrations.base import ExternalToolAdapter, register_tool

_IMPACT = {
    "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW,
    "informational": Severity.INFO, "optimization": Severity.INFO,
}
_CONFIDENCE = {"high": Confidence.CONFIRMED, "medium": Confidence.FIRM, "low": Confidence.TENTATIVE}

# a few well-known detectors → the web3 ontology class; default keeps the check name.
_CLASS = {
    "reentrancy-eth": "reentrancy", "reentrancy-no-eth": "reentrancy",
    "reentrancy-benign": "reentrancy", "arbitrary-send-eth": "access-control.unrestricted",
    "suicidal": "access-control.unrestricted", "unprotected-upgrade": "access-control.unrestricted",
    "tx-origin": "access-control.unrestricted", "weak-prng": "oracle.manipulation",
}


def _first_location(element_list) -> str | None:
    for el in element_list or []:
        sm = (el.get("source_mapping") or {}) if isinstance(el, dict) else {}
        fn = sm.get("filename_relative") or sm.get("filename_short")
        if fn:
            lines = sm.get("lines") or []
            return f"{fn}:{lines[0]}" if lines else fn
    return None


def parse_slither_json(stdout: str, target: str) -> list[Finding]:
    """Map slither ``--json -`` output to web3 Findings (pure)."""
    text = (stdout or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    detectors = (((data or {}).get("results") or {}).get("detectors")) or []
    findings: list[Finding] = []
    for det in detectors:
        if not isinstance(det, dict):
            continue
        check = str(det.get("check") or "detector")
        loc = _first_location(det.get("elements")) or target
        findings.append(
            Finding(
                vuln_type=_CLASS.get(check, "smart-contract"),
                title=f"[slither] {check}",
                severity=_IMPACT.get(str(det.get("impact", "")).lower(), Severity.LOW),
                confidence=_CONFIDENCE.get(str(det.get("confidence", "")).lower(), Confidence.FIRM),
                url=str(loc),
                description=str(det.get("description") or f"Slither detector '{check}' fired.").strip()[:800],
                remediation="Review the flagged contract logic; follow the detector's guidance.",
                scanner="slither",
                evidence=Evidence(notes=f"slither check={check} impact={det.get('impact')} "
                                        f"confidence={det.get('confidence')}"),
            )
        )
    return findings


@register_tool
class SlitherAdapter(ExternalToolAdapter):
    name = "slither"
    binary = "slither"
    default_timeout = 600.0

    def build_command(self, target: str) -> list[str]:
        return [self.binary, target, "--json", "-"]

    def parse_output(self, stdout: str, target: str) -> list[Finding]:
        return parse_slither_json(stdout, target)


__all__ = ["SlitherAdapter", "parse_slither_json"]
