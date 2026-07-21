"""mobsfscan adapter - normalize the mobile SAST engine's JSON (PRD Phase 5, mobile).

mobsfscan (the CLI companion to MobSF) statically analyzes Android/iOS source and
emits ``--json`` to stdout - a clean fit for this framework. Each rule hit becomes a
Finding: ERROR/WARNING/INFO -> severity, CWE + OWASP-MASVS carried through, first
file:line as the location, so mobile findings flow through the same pipeline as web.
"""

from __future__ import annotations

import json

from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.integrations.base import ExternalToolAdapter, register_tool

_SEV = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "info": Severity.LOW}


def parse_mobsfscan_json(stdout: str, target: str) -> list[Finding]:
    """Map mobsfscan ``--json`` output to mobile-SAST Findings (pure)."""
    text = (stdout or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    results = (data.get("results") if isinstance(data, dict) else None) or {}
    findings: list[Finding] = []
    for rule_id, entry in results.items():
        if not isinstance(entry, dict):
            continue
        meta = entry.get("metadata") or {}
        files = entry.get("files") or []
        first = files[0] if files and isinstance(files[0], dict) else {}
        path = str(first.get("file_path") or target)
        lines = first.get("match_lines") or []
        loc = f"{path}:{lines[0]}" if isinstance(lines, list) and lines else path
        cwe = str(meta.get("cwe") or "").strip() or None
        findings.append(
            Finding(
                vuln_type="mobile-sast",
                title=f"[mobsfscan] {rule_id}"[:140],
                severity=_SEV.get(str(meta.get("severity") or "").lower(), Severity.LOW),
                confidence=Confidence.FIRM,
                url=loc,
                description=str(meta.get("description") or "mobsfscan rule matched.").strip()[:800],
                remediation="Review the flagged code against the rule's MASVS/OWASP guidance.",
                cwe=cwe,
                scanner="mobsfscan",
                evidence=Evidence(notes=f"mobsfscan rule={rule_id} "
                                        f"owasp={meta.get('owasp-mobile')} masvs={meta.get('masvs')}"),
            )
        )
    return findings


@register_tool
class MobsfscanAdapter(ExternalToolAdapter):
    name = "mobsfscan"
    binary = "mobsfscan"
    default_timeout = 900.0

    def build_command(self, target: str) -> list[str]:
        return [self.binary, "--json", target]

    def parse_output(self, stdout: str, target: str) -> list[Finding]:
        return parse_mobsfscan_json(stdout, target)


__all__ = ["MobsfscanAdapter", "parse_mobsfscan_json"]
