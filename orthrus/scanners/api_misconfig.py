"""API / HTTP method misconfiguration scanner (XST + dangerous methods).

Two deterministic, low-false-positive probes per origin (no payload reflection,
no status-code-only heuristics):

1. **Cross-Site Tracing (TRACE/XST)** — send a TRACE request carrying a unique
   custom header. A server with TRACE enabled echoes the whole request back in
   the body, so seeing the nonce in a 200 response proves the method is on. With
   TRACE, an attacker can read ``HttpOnly`` cookies and auth headers via XSS.
2. **Dangerous methods advertised** — send OPTIONS and read the ``Allow`` /
   ``Access-Control-Allow-Methods`` header. If the server advertises write or
   otherwise risky verbs (PUT/DELETE/PATCH/TRACE/CONNECT) they are reported so an
   operator can confirm they are intended and properly authorized.

Both probes are deduped per origin per check and bounded by ``MAX_ORIGINS``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.api-misconfig")

SCANNER_NAME = "api-misconfig"
MAX_ORIGINS = 3

# Unique marker echoed back by a TRACE-enabled server, proving XST.
_XST_NONCE = "Orthrus-Xst-9c4f2a"
_XST_HEADER = "X-Orthrus-Xst"

# Verbs that are write/dangerous when advertised on a public host.
_DANGEROUS_METHODS: tuple[str, ...] = ("PUT", "DELETE", "PATCH", "TRACE", "CONNECT")


def trace_enabled(status: int, body: str, nonce: str) -> bool:
    """True if a TRACE request was echoed back (200 + nonce in body) -> XST."""
    return status == 200 and nonce in body


def dangerous_methods(allow_header: str) -> list[str]:
    """Return the dangerous verbs advertised in an Allow / ACAM header value."""
    advertised = {m.strip().upper() for m in allow_header.split(",") if m.strip()}
    return [method for method in _DANGEROUS_METHODS if method in advertised]


def origins_from(target: str, endpoint_urls: Iterable[str]) -> list[str]:
    """Distinct ``scheme://host`` origins from the target + discovered endpoints."""
    seen: list[str] = []
    for url in (target, *endpoint_urls):
        parts = urlsplit(url)
        if parts.scheme and parts.netloc:
            origin = f"{parts.scheme}://{parts.netloc}"
            if origin not in seen:
                seen.append(origin)
    return seen


@register
class ApiMisconfigScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "api-misconfig"
    min_aggressiveness = Aggressiveness.NORMAL

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        emitted: set[tuple[str, str]] = set()
        origins = origins_from(ctx.config.target, [ep.url for ep in ctx.endpoints])[:MAX_ORIGINS]

        for origin in origins:
            if not ctx.scope.is_allowed(origin):
                continue

            # 1) Cross-Site Tracing (TRACE/XST).
            if (origin, "xst") not in emitted:
                resp = await self._trace(ctx, origin)
                if resp is not None and trace_enabled(resp.status_code, resp.text, _XST_NONCE):
                    emitted.add((origin, "xst"))
                    yield self._xst_finding(origin)

            # 2) Dangerous methods advertised via OPTIONS.
            if (origin, "methods") not in emitted:
                resp = await self._options(ctx, origin)
                if resp is not None:
                    allow = self._allow_header(resp.headers)
                    methods = dangerous_methods(allow)
                    if methods:
                        emitted.add((origin, "methods"))
                        yield self._methods_finding(origin, methods, allow)

    async def _trace(self, ctx: ScanContext, origin: str) -> httpx.Response | None:
        try:
            return await ctx.http.request(
                "TRACE",
                origin,
                headers={_XST_HEADER: _XST_NONCE},
                follow_redirects=False,
            )
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("TRACE probe failed for %s: %s", origin, exc)
            return None

    async def _options(self, ctx: ScanContext, origin: str) -> httpx.Response | None:
        try:
            return await ctx.http.request("OPTIONS", origin, follow_redirects=False)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("OPTIONS probe failed for %s: %s", origin, exc)
            return None

    @staticmethod
    def _allow_header(headers: dict[str, str]) -> str:
        lower = {k.lower(): v for k, v in headers.items()}
        return lower.get("allow") or lower.get("access-control-allow-methods") or ""

    def _xst_finding(self, origin: str) -> Finding:
        return Finding(
            vuln_type="api-misconfig",
            title="HTTP TRACE method enabled (Cross-Site Tracing)",
            severity=Severity.MEDIUM,
            confidence=Confidence.FIRM,
            url=origin,
            description=(
                "The server honours the HTTP TRACE method and echoes the request back in the "
                "response body. Combined with a client-side flaw, Cross-Site Tracing (XST) lets "
                "an attacker read otherwise-protected headers such as HttpOnly session cookies "
                "and Authorization tokens, bypassing the HttpOnly cookie protection."
            ),
            remediation=(
                "Disable the TRACE (and TRACK) method at the web server / reverse proxy. For "
                "Apache set TraceEnable Off; for Nginx reject the method; for IIS disable "
                "verb handling for TRACE."
            ),
            cwe="CWE-693",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                matched_at=_XST_NONCE,
                notes="TRACE returned 200 with the custom request header echoed in the body",
                request_raw=f"TRACE {origin} ({_XST_HEADER}: {_XST_NONCE[:4]}***)",
            ),
        )

    def _methods_finding(self, origin: str, methods: list[str], allow: str) -> Finding:
        joined = ", ".join(methods)
        return Finding(
            vuln_type="api-misconfig",
            title=f"Server advertises write/dangerous HTTP methods: {joined}",
            severity=Severity.LOW,
            confidence=Confidence.FIRM,
            url=origin,
            description=(
                "An OPTIONS request shows the server advertises potentially dangerous HTTP "
                f"methods ({joined}). Write methods such as PUT/DELETE/PATCH may allow content "
                "modification or deletion if not strictly authorized, and TRACE/CONNECT enable "
                "Cross-Site Tracing and proxy abuse. Confirm each method is intended and gated "
                "by authentication and authorization."
            ),
            remediation=(
                "Restrict allowed methods to those each endpoint requires. Disable TRACE/CONNECT "
                "globally and ensure PUT/DELETE/PATCH are authenticated and authorized (or "
                "removed) on public hosts."
            ),
            cwe="CWE-16",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                matched_at=allow,
                notes="dangerous verbs advertised in the Allow / Access-Control-Allow-Methods header",
            ),
        )


__all__ = [
    "ApiMisconfigScanner",
    "trace_enabled",
    "dangerous_methods",
    "origins_from",
]
