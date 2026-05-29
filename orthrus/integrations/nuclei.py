"""Nuclei adapter — run ProjectDiscovery's nuclei and normalize its JSONL output.

Nuclei brings a huge community template ecosystem (CVEs, misconfigurations,
exposures, default creds, takeovers). This adapter runs it against the target and
maps each JSONL hit to an ORTHRUS Finding, carrying nuclei's own severity.
"""

from __future__ import annotations

import json

from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.integrations.base import ExternalToolAdapter, register_tool

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


def _first_cwe(info: dict) -> str | None:
    classification = info.get("classification") or {}
    cwe = classification.get("cwe-id") or classification.get("cwe_id")
    if isinstance(cwe, list) and cwe:
        return str(cwe[0]).upper()
    if isinstance(cwe, str) and cwe:
        return cwe.upper()
    return None


def parse_nuclei_jsonl(stdout: str, target: str) -> list[Finding]:
    """Map nuclei JSONL lines to Findings (pure)."""
    findings: list[Finding] = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        info = obj.get("info") or {}
        template_id = obj.get("template-id") or obj.get("templateID") or "nuclei"
        name = info.get("name") or template_id
        sev = _SEVERITY.get(str(info.get("severity", "info")).lower(), Severity.INFO)
        url = obj.get("matched-at") or obj.get("matched_at") or obj.get("host") or target
        description = (info.get("description") or f"Nuclei template '{template_id}' matched.").strip()
        findings.append(
            Finding(
                vuln_type="tool-nuclei",
                title=f"[nuclei] {name}",
                severity=sev,
                confidence=Confidence.FIRM,
                url=str(url),
                description=description[:600],
                remediation=(
                    info.get("remediation")
                    or "Review the matched nuclei template and referenced advisory, then remediate."
                ).strip()[:400],
                cwe=_first_cwe(info),
                scanner="nuclei",
                evidence=Evidence(
                    matched_at=str(url),
                    notes=f"nuclei template-id={template_id} severity={info.get('severity', 'info')}",
                ),
            )
        )
    return findings


@register_tool
class NucleiAdapter(ExternalToolAdapter):
    name = "nuclei"
    binary = "nuclei"
    default_timeout = 900.0

    def build_command(self, target: str) -> list[str]:
        return [
            self.binary,
            "-target", target,
            "-jsonl",
            "-silent",
            "-no-color",
            "-disable-update-check",
        ]

    def parse_output(self, stdout: str, target: str) -> list[Finding]:
        return parse_nuclei_jsonl(stdout, target)


__all__ = ["NucleiAdapter", "parse_nuclei_jsonl"]
