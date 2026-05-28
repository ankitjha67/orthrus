"""Web cache poisoning scanner (PRD §6.8 Cache Poisoning).

Injects unkeyed headers (X-Forwarded-Host, X-Forwarded-Scheme, ...) and checks
whether the marker is reflected into the response body or headers. Reflection of
an unkeyed header that influences a cacheable response is the precondition for
poisoning; cacheability indicators raise the severity.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from hydra.core.context import ScanContext
from hydra.core.schemas import Confidence, Evidence, Finding, Severity
from hydra.scanners.base_scanner import BaseScanner
from hydra.scanners.registry import register
from hydra.utils.logger import get_logger
from hydra.utils.scope import ScopeViolation

logger = get_logger("scanner.cache")

SCANNER_NAME = "cache-poisoning"
MAX_URLS = 40
MARKER = "hydra-cache.example"

UNKEYED_HEADERS = {
    "X-Forwarded-Host": MARKER,
    "X-Forwarded-Server": MARKER,
    "X-Host": MARKER,
    "X-Forwarded-Scheme": "http",
}

_CACHE_INDICATORS = ("x-cache", "age", "cf-cache-status", "x-cache-hits", "x-varnish")


def reflects_marker(body: str, headers: dict[str, str], marker: str = MARKER) -> bool:
    if marker in body:
        return True
    return any(marker in value for value in headers.values())


def is_cacheable(headers: dict[str, str]) -> bool:
    lower = {k.lower(): v.lower() for k, v in headers.items()}
    if any(ind in lower for ind in _CACHE_INDICATORS):
        return True
    cache_control = lower.get("cache-control", "")
    return "public" in cache_control or "max-age" in cache_control


@register
class CachePoisoningScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "cache-poisoning"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen_urls: set[str] = set()
        seen_findings: set[str] = set()
        candidates = [ctx.config.target, *[ep.url for ep in ctx.endpoints]]
        tested = 0

        for url in candidates:
            if tested >= MAX_URLS:
                break
            norm = url.split("#", 1)[0]
            if norm in seen_urls or not ctx.scope.is_allowed(norm):
                continue
            seen_urls.add(norm)
            tested += 1

            try:
                resp = await ctx.http.get(norm, headers=UNKEYED_HEADERS, follow_redirects=False)
            except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
                logger.debug("cache probe failed for %s: %s", norm, exc)
                continue

            headers = dict(resp.headers)
            if not reflects_marker(resp.text, headers):
                continue

            host = urlsplit(norm).netloc
            if host in seen_findings:
                continue
            seen_findings.add(host)

            cacheable = is_cacheable(headers)
            yield Finding(
                vuln_type="cache-poisoning",
                title="Unkeyed header reflected (web cache poisoning candidate)",
                severity=Severity.MEDIUM if cacheable else Severity.LOW,
                confidence=Confidence.FIRM if cacheable else Confidence.TENTATIVE,
                url=norm,
                description=(
                    "An unkeyed request header (e.g. X-Forwarded-Host) is reflected into the "
                    f"response{' and the response shows cache indicators' if cacheable else ''}. "
                    "If this response is cached, an attacker can poison it for other users."
                ),
                remediation=(
                    "Do not reflect unkeyed request headers into responses; include all influential "
                    "headers in the cache key, or strip X-Forwarded-* at the edge."
                ),
                cwe="CWE-444",
                scanner=SCANNER_NAME,
                evidence=Evidence(
                    request_raw=f"X-Forwarded-Host: {MARKER}",
                    matched_at=MARKER,
                    notes="cacheable response" if cacheable else "reflection without cache headers",
                ),
            )


__all__ = ["CachePoisoningScanner", "reflects_marker", "is_cacheable"]
