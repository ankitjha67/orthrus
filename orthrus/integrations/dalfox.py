"""Dalfox adapter — run the popular XSS scanner and normalize its JSON output.

Dalfox (hahwul) is a staple of the bounty XSS workflow. This adapter runs it
against the target and maps each proof-of-concept object to an ORTHRUS XSS
Finding, carrying dalfox's payload and PoC URL as evidence.
"""

from __future__ import annotations

import json

from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.integrations.base import ExternalToolAdapter, register_tool

_SEVERITY = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
    "low": Severity.LOW, "info": Severity.INFO, "unknown": Severity.INFO,
}
# dalfox 'type': V=verified (browser-executed), R=reflected, G=grep/other.
_CONFIDENCE = {"V": Confidence.CONFIRMED, "R": Confidence.FIRM, "G": Confidence.TENTATIVE}


def _iter_objects(stdout: str):
    """Yield dalfox PoC dicts from stdout (a JSON array or JSON-lines)."""
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
        line = raw.strip()
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict):
                yield obj


def parse_dalfox_json(stdout: str, target: str) -> list[Finding]:
    """Map dalfox JSON PoCs to XSS Findings (pure)."""
    findings: list[Finding] = []
    for obj in _iter_objects(stdout):
        poc = obj.get("data") or obj.get("poc") or obj.get("evidence") or target
        payload = obj.get("data") or obj.get("payload") or ""
        sev = _SEVERITY.get(str(obj.get("severity", "medium")).lower(), Severity.MEDIUM)
        conf = _CONFIDENCE.get(str(obj.get("type", "R")).upper(), Confidence.FIRM)
        param = obj.get("param") or obj.get("inject_type") or None
        findings.append(
            Finding(
                vuln_type="xss",
                title="[dalfox] Cross-site scripting",
                severity=sev,
                confidence=conf,
                url=str(poc),
                parameter=param,
                description=(obj.get("message_str") or "Dalfox identified a cross-site scripting "
                            "vector; the payload is reflected/executed at the PoC URL.").strip()[:600],
                remediation="Context-encode output and apply a strict Content-Security-Policy.",
                cwe=obj.get("cwe") or "CWE-79",
                scanner="dalfox",
                evidence=Evidence(
                    matched_at=str(obj.get("evidence") or payload)[:400],
                    notes=f"dalfox type={obj.get('type', '?')} payload={str(payload)[:200]}",
                ),
            )
        )
    return findings


@register_tool
class DalfoxAdapter(ExternalToolAdapter):
    name = "dalfox"
    binary = "dalfox"
    default_timeout = 600.0

    def build_command(self, target: str) -> list[str]:
        return [self.binary, "url", target, "--format", "json", "--silence", "--no-color", "--skip-bav"]

    def parse_output(self, stdout: str, target: str) -> list[Finding]:
        return parse_dalfox_json(stdout, target)


__all__ = ["DalfoxAdapter", "parse_dalfox_json"]
