"""Checkov adapter - normalize the IaC/cloud misconfig scanner's JSON (PRD Phase 5, cloud).

Checkov scans Terraform / CloudFormation / Kubernetes / etc. for misconfigurations.
Each failed check becomes a Finding (severity from checkov when present), carrying
the file/resource as evidence - cloud posture findings in the same pipeline.
"""

from __future__ import annotations

import json

from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.integrations.base import ExternalToolAdapter, register_tool

_SEV = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
    "low": Severity.LOW, "info": Severity.INFO,
}


def _iter_failed(data):
    """Yield failed_checks across checkov's list-of-reports or single-report shapes."""
    reports = data if isinstance(data, list) else [data]
    for report in reports:
        if not isinstance(report, dict):
            continue
        for check in ((report.get("results") or {}).get("failed_checks")) or []:
            if isinstance(check, dict):
                yield check


def parse_checkov_json(stdout: str, target: str) -> list[Finding]:
    """Map checkov JSON output to cloud/IaC misconfiguration Findings (pure)."""
    text = (stdout or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    findings: list[Finding] = []
    for check in _iter_failed(data):
        sev = _SEV.get(str(check.get("severity") or "").lower(), Severity.MEDIUM)
        path = str(check.get("file_path") or target)
        rng = check.get("file_line_range") or []
        loc = f"{path}:{rng[0]}" if rng else path
        findings.append(
            Finding(
                vuln_type="cloud-misconfig",
                title=f"[checkov] {check.get('check_name') or check.get('check_id') or 'misconfiguration'}"[:140],
                severity=sev,
                confidence=Confidence.FIRM,
                url=loc,
                description=(f"{check.get('check_name') or ''} "
                            f"(resource: {check.get('resource') or 'n/a'}). "
                            f"{check.get('guideline') or ''}").strip()[:800],
                remediation="Apply the guideline for this control and re-scan.",
                scanner="checkov",
                evidence=Evidence(notes=f"checkov {check.get('check_id')} resource={check.get('resource')}"),
            )
        )
    return findings


@register_tool
class CheckovAdapter(ExternalToolAdapter):
    name = "checkov"
    binary = "checkov"
    default_timeout = 600.0

    def build_command(self, target: str) -> list[str]:
        return [self.binary, "-d", target, "-o", "json", "--compact", "--quiet"]

    def parse_output(self, stdout: str, target: str) -> list[Finding]:
        return parse_checkov_json(stdout, target)


__all__ = ["CheckovAdapter", "parse_checkov_json"]
