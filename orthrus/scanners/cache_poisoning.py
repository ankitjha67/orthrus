"""Web cache poisoning scanner (PRD §6.8 Cache Poisoning).

Injects unkeyed headers (X-Forwarded-Host, X-Forwarded-Scheme, ...) and checks
whether the marker is reflected into the response body or headers. Reflection of
an unkeyed header that influences a cacheable response is the precondition for
poisoning; cacheability indicators raise the severity.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.cache")

SCANNER_NAME = "cache-poisoning"
MAX_URLS = 40
MARKER = "orthrus-cache.example"

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
            # Active confirmation: if the response looks cacheable, prove the cache
            # actually serves the attacker value by re-fetching a cache-buster key
            # *without* the header and checking the marker comes back from cache.
            if cacheable and await self._confirm_poisoning(ctx, norm):
                yield Finding(
                    vuln_type="cache-poisoning",
                    title="Confirmed web cache poisoning (clean request served attacker value)",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    url=norm,
                    description=(
                        "After injecting an unkeyed header (X-Forwarded-Host) on a unique "
                        "cache-buster URL, a subsequent *clean* request (no injected header) to the "
                        "same URL returned the attacker-controlled value - proving the cache stored "
                        "and serves a response an attacker fully controls to every other visitor of "
                        "that page. (Testing used a cache-buster, so only the throwaway key was "
                        "poisoned, not production URLs.)"
                    ),
                    remediation=(
                        "Do not reflect unkeyed request headers into responses; include all "
                        "influential headers in the cache key, or strip X-Forwarded-* at the edge."
                    ),
                    cwe="CWE-444",
                    scanner=SCANNER_NAME,
                    evidence=Evidence(
                        request_raw=f"X-Forwarded-Host: {MARKER} (then a clean re-fetch)",
                        matched_at=MARKER,
                        notes="clean request to the cache-buster URL served the poisoned marker",
                    ),
                )
                continue

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

    async def _confirm_poisoning(self, ctx: ScanContext, url: str) -> bool:
        """Prove the cache serves the attacker value to a clean request.

        Poison a unique cache-buster key with the unkeyed header, then re-fetch the
        same key *without* the header. If the marker comes back, the cache stored
        and serves the attacker-controlled response. The cache-buster isolates the
        poison to a throwaway URL so production pages are never affected.
        """
        sep = "&" if "?" in url else "?"
        probe_url = f"{url}{sep}orthrus_cb={secrets.token_hex(6)}"
        try:
            poisoned = await ctx.http.get(
                probe_url, headers=UNKEYED_HEADERS, follow_redirects=False
            )
            if MARKER not in poisoned.text:
                return False
            clean = await ctx.http.get(probe_url, follow_redirects=False)
            return MARKER in clean.text
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("cache-poison confirmation failed for %s: %s", url, exc)
            return False


__all__ = ["CachePoisoningScanner", "reflects_marker", "is_cacheable"]
