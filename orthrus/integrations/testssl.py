"""testssl.sh adapter — run the TLS auditor and normalize its JSON findings.

testssl.sh is the reference TLS/SSL tester (protocols, ciphers, known CVEs like
Heartbleed/ROBOT/BEAST). This adapter runs it with ``--jsonfile-pretty`` streamed
to stdout and maps each non-OK finding to an ORTHRUS TLS Finding.
"""

from __future__ import annotations

import json

from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.integrations.base import ExternalToolAdapter, register_tool

# testssl severities: DEBUG/INFO/OK/LOW/MEDIUM/HIGH/CRITICAL/WARN.
_SEVERITY = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}
_SKIP = {"OK", "INFO", "DEBUG", "WARN"}


def _iter_records(stdout: str):
    text = stdout.strip()
    if text.startswith("["):
        try:
            arr = json.loads(text)
            if isinstance(arr, list):
                yield from (o for o in arr if isinstance(o, dict))
                return
        except ValueError:
            pass
    for raw in text.splitlines():
        line = raw.strip().rstrip(",")
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict):
                yield obj


def parse_testssl_json(stdout: str, target: str) -> list[Finding]:
    """Map testssl.sh JSON records (severity above OK/INFO) to TLS Findings (pure)."""
    findings: list[Finding] = []
    for obj in _iter_records(stdout):
        sev_raw = str(obj.get("severity", "")).upper()
        if sev_raw in _SKIP or sev_raw not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            continue
        rid = obj.get("id") or "tls"
        finding_txt = (obj.get("finding") or "").strip()
        cve = obj.get("cve") or ""
        findings.append(
            Finding(
                vuln_type="tls",
                title=f"[testssl] {rid}",
                severity=_SEVERITY.get(sev_raw.lower(), Severity.LOW),
                confidence=Confidence.FIRM,
                url=f"https://{target}" if "://" not in target else target,
                description=(finding_txt or f"testssl.sh flagged '{rid}'.")[:600],
                remediation="Harden the TLS configuration: disable weak protocols/ciphers and "
                            "patch the referenced CVE(s).",
                cwe="CWE-326",
                scanner="testssl",
                evidence=Evidence(matched_at=finding_txt[:400] or rid,
                                  notes=f"testssl id={rid} severity={sev_raw}"
                                        + (f" cve={cve}" if cve else "")),
            )
        )
    return findings


@register_tool
class TestsslAdapter(ExternalToolAdapter):
    name = "testssl"
    binary = "testssl.sh"
    default_timeout = 600.0

    def build_command(self, target: str) -> list[str]:
        host = target.split("://", 1)[-1].rstrip("/")
        return [self.binary, "--quiet", "--color", "0", "--jsonfile-pretty", "/dev/stdout", host]

    def parse_output(self, stdout: str, target: str) -> list[Finding]:
        return parse_testssl_json(stdout, target)


__all__ = ["TestsslAdapter", "parse_testssl_json"]
