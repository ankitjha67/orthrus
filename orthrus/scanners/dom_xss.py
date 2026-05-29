"""DOM-based XSS scanner (PRD §6.3 DOM-Based XSS).

Uses the real headless browser to inject executing payloads into client-side
sources (the URL fragment and query parameters) and detects whether they reach
a dangerous sink and execute. Because detection here *is* execution in a real
DOM, findings are emitted as CONFIRMED with a screenshot. Browser-gated.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator, Callable
from urllib.parse import quote, urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, HttpMethod, ParamLocation, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.scanners.xss import execution_payloads
from orthrus.utils.encoding import with_query_param
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.dom-xss")

SCANNER_NAME = "dom-xss"
MAX_PROBES = 40

UrlBuilder = Callable[[str, str], str]


@register
class DomXssScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "xss"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        if ctx.browser is None:
            logger.debug("dom-xss: no browser engine; skipping")
            return

        probes = 0
        seen_paths: set[str] = set()
        for endpoint in ctx.endpoints:
            if endpoint.method != HttpMethod.GET or probes >= MAX_PROBES:
                continue
            base = endpoint.url.split("#", 1)[0]
            path = urlsplit(base).path

            # 1) URL fragment (hash) source — test once per path.
            if path not in seen_paths:
                seen_paths.add(path)
                probes += 1
                finding = await self._probe_source(
                    ctx, base, "URL fragment", None, None,
                    lambda b, p: f"{b}#{quote(p, safe='')}",
                )
                if finding is not None:
                    yield finding

            # 2) Query-parameter sources.
            for param in {p.name for p in endpoint.params if p.location == ParamLocation.QUERY}:
                if probes >= MAX_PROBES:
                    break
                probes += 1
                finding = await self._probe_source(
                    ctx,
                    base,
                    f"parameter '{param}'",
                    param,
                    ParamLocation.QUERY,
                    lambda b, p, _name=param: with_query_param(b, _name, p),
                )
                if finding is not None:
                    yield finding

    async def _probe_source(
        self,
        ctx: ScanContext,
        base: str,
        source_label: str,
        param_name: str | None,
        param_location: ParamLocation | None,
        build_url: UrlBuilder,
    ) -> Finding | None:
        assert ctx.browser is not None
        for template in execution_payloads("__MARK__"):
            marker = "hdx" + secrets.token_hex(4)
            payload = template.replace("__MARK__", marker)
            target = build_url(base, payload)
            if not ctx.scope.is_allowed(target):
                continue
            # Discriminator: if the marker comes back in the *raw* server response,
            # this is server-reflected XSS (reflected-xss owns it), not DOM-based.
            try:
                raw = await ctx.http.get(target)
                if marker in raw.text:
                    continue
            except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL):
                pass
            probe = await ctx.browser.check_execution(
                target, marker, screenshot_name=f"domxss-{marker}"
            )
            if probe.executed:
                return Finding(
                    vuln_type="xss",
                    title=f"DOM-based XSS via {source_label}",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    url=target,
                    parameter=param_name,
                    param_location=param_location,
                    description=(
                        f"A payload injected via the {source_label} executed in the browser "
                        f"(proof via {probe.method}). Client-side code writes attacker input to a "
                        "dangerous sink (e.g. innerHTML/eval) without sanitization."
                    ),
                    remediation=(
                        "Avoid writing untrusted data to dangerous sinks; use textContent / safe "
                        "DOM APIs, sanitize with a trusted library, and apply a strict CSP."
                    ),
                    cwe="CWE-79",
                    scanner=SCANNER_NAME,
                    evidence=Evidence(
                        request_raw=target,
                        screenshot_path=probe.screenshot_path,
                        notes=f"executed in headless browser via {probe.method}",
                    ),
                )
        return None


__all__ = ["DomXssScanner"]
