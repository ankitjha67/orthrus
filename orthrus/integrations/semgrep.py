"""Semgrep adapter - normalize the SAST engine's JSON (PRD Phase 5, code).

Semgrep covers source-code security across many languages (and smart contracts).
Each result becomes a Finding: ERROR/WARNING/INFO → severity, CWE lifted from the
rule metadata, file:line as the location.
"""

from __future__ import annotations

import json

from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.integrations.base import ExternalToolAdapter, register_tool

_SEV = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "info": Severity.LOW}


def parse_semgrep_json(stdout: str, target: str) -> list[Finding]:
    """Map semgrep ``--json`` output to SAST Findings (pure)."""
    text = (stdout or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    findings: list[Finding] = []
    for res in (data.get("results") if isinstance(data, dict) else []) or []:
        if not isinstance(res, dict):
            continue
        extra = res.get("extra") or {}
        meta = extra.get("metadata") or {}
        cwe = meta.get("cwe")
        cwe_id = (cwe[0] if isinstance(cwe, list) and cwe else cwe) if cwe else None
        path = str(res.get("path") or target)
        line = (res.get("start") or {}).get("line")
        rule = str(res.get("check_id") or "finding").split(".")[-1]
        findings.append(
            Finding(
                vuln_type="sast",
                title=f"[semgrep] {rule}"[:140],
                severity=_SEV.get(str(extra.get("severity") or "").lower(), Severity.LOW),
                confidence=Confidence.FIRM,
                url=f"{path}:{line}" if line else path,
                description=str(extra.get("message") or "Semgrep rule matched.").strip()[:800],
                remediation="Review the matched code against the rule's guidance.",
                cwe=str(cwe_id) if cwe_id else None,
                scanner="semgrep",
                evidence=Evidence(notes=f"semgrep rule={res.get('check_id')}"),
            )
        )
    return findings


@register_tool
class SemgrepAdapter(ExternalToolAdapter):
    name = "semgrep"
    binary = "semgrep"
    default_timeout = 900.0

    def build_command(self, target: str) -> list[str]:
        return [self.binary, "scan", "--json", "--quiet", "--config", "auto", target]

    def parse_output(self, stdout: str, target: str) -> list[Finding]:
        return parse_semgrep_json(stdout, target)


__all__ = ["SemgrepAdapter", "parse_semgrep_json"]
