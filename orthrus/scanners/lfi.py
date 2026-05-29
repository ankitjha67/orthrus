"""Local file inclusion / path traversal scanner (PRD §6.5).

Attempts to read well-known files (/etc/passwd, Windows win.ini) via traversal
payloads with depth and encoding variants, then matches their distinctive
signatures in the response. Read-only; extracted content is not stored verbatim.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from orthrus.scanners._injection import InjectionPoint, injection_points, send, used_url
from orthrus.scanners._payloads import LFI_PATHS
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register

SCANNER_NAME = "lfi"
MAX_POINTS = 120

LFI_PAYLOADS = LFI_PATHS

_PASSWD_RE = re.compile(r"root:.*?:0:0:", re.MULTILINE)
_WININI_RE = re.compile(r"\[(fonts|extensions|mci extensions)\]|for 16-bit app support", re.IGNORECASE)


def detect_lfi(body: str) -> str | None:
    """Return the file label whose signature is present, else None."""
    if _PASSWD_RE.search(body):
        return "/etc/passwd"
    if _WININI_RE.search(body):
        return "C:\\windows\\win.ini"
    return None


def _param_value(point: InjectionPoint) -> str:
    for p in point.endpoint.params:
        if p.name == point.param:
            return p.value or ""
    return ""


@register
class LfiScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "lfi"
    min_aggressiveness = Aggressiveness.NORMAL

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        count = 0
        for point in injection_points(ctx):
            if count >= MAX_POINTS:
                break
            count += 1

            baseline = await send(ctx, point, _param_value(point))
            if baseline is not None and detect_lfi(baseline.text):
                continue  # file signature already present unprovoked -> skip

            for payload in LFI_PAYLOADS:
                resp = await send(ctx, point, payload)
                if resp is None:
                    continue
                matched = detect_lfi(resp.text)
                if matched:
                    yield Finding(
                        vuln_type="lfi",
                        title=f"Local file inclusion / path traversal in '{point.param}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.FIRM,
                        url=used_url(point, payload),
                        parameter=point.param,
                        param_location=point.location,
                        description=(
                            f"Parameter '{point.param}' allows reading arbitrary files; the "
                            f"contents of {matched} were returned. This can expose credentials, "
                            "source code, and configuration."
                        ),
                        remediation=(
                            "Do not build filesystem paths from user input. Use allow-lists of "
                            "permitted files/IDs, canonicalize and confine paths to a base dir."
                        ),
                        cwe="CWE-22",
                        scanner=SCANNER_NAME,
                        evidence=Evidence(
                            request_raw=f"{point.param}={payload}",
                            matched_at=matched,
                            notes=f"signature for {matched} found in response",
                        ),
                    )
                    break


__all__ = ["LfiScanner", "detect_lfi"]
