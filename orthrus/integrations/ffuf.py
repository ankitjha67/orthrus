"""ffuf adapter - content/endpoint discovery, normalized to Findings.

ffuf brute-forces paths/endpoints; the hits it returns are the hidden attack
surface a hunter cares about (admin panels, backups, API routes). This adapter
maps each ffuf result to a discovery Finding - informational by default, low when
the path is reachable (2xx) or explicitly forbidden (401/403), which are the
interesting ones. Needs a wordlist via ``ORTHRUS_FFUF_WORDLIST``.
"""

from __future__ import annotations

import json
import os

from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.integrations.base import ExternalToolAdapter, register_tool

# Statuses worth a low (not just info) rating - reachable or gated-but-present.
_LOW_STATUS = {200, 204, 401, 403}


def parse_ffuf_json(stdout: str, target: str) -> list[Finding]:
    """Map ffuf JSON results to content-discovery Findings (pure)."""
    text = stdout.strip()
    if not text.startswith("{"):
        return []
    try:
        obj = json.loads(text)
    except ValueError:
        return []
    findings: list[Finding] = []
    for r in obj.get("results", []):
        if not isinstance(r, dict):
            continue
        url = r.get("url") or target
        status = int(r.get("status", 0) or 0)
        length = r.get("length")
        sev = Severity.LOW if status in _LOW_STATUS else Severity.INFO
        findings.append(
            Finding(
                vuln_type="content-discovery",
                title=f"[ffuf] Discovered path ({status})",
                severity=sev,
                confidence=Confidence.FIRM,
                url=str(url),
                description=f"Content discovery surfaced {url} (HTTP {status}); review whether it "
                           "exposes sensitive functionality or data.",
                remediation="Remove or authenticate unintended endpoints; don't rely on obscurity.",
                scanner="ffuf",
                evidence=Evidence(matched_at=str(url),
                                  notes=f"ffuf status={status} length={length}"),
            )
        )
    return findings


@register_tool
class FfufAdapter(ExternalToolAdapter):
    name = "ffuf"
    binary = "ffuf"
    default_timeout = 600.0

    def build_command(self, target: str) -> list[str]:
        wordlist = os.environ.get("ORTHRUS_FFUF_WORDLIST", "/usr/share/seclists/Discovery/Web-Content/common.txt")
        base = target.rstrip("/")
        return [self.binary, "-u", f"{base}/FUZZ", "-w", wordlist, "-json", "-s",
                "-mc", "200,204,301,302,307,401,403,405,500"]

    def parse_output(self, stdout: str, target: str) -> list[Finding]:
        return parse_ffuf_json(stdout, target)


__all__ = ["FfufAdapter", "parse_ffuf_json"]
