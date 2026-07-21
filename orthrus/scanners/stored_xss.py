"""Stored XSS scanner (PRD §6.3 Stored XSS).

Submits an executing payload through writable POST forms, then re-renders
candidate pages in the headless browser to detect whether the payload persisted
and executed for a subsequent visitor. Execution in a real DOM means findings
are emitted CONFIRMED with a screenshot. Browser-gated.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, HttpMethod, ParamLocation, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.stored-xss")

SCANNER_NAME = "stored-xss"
MAX_FORMS = 8
MAX_REVIEW_PAGES = 10


def _payload(marker: str) -> str:
    # onerror fires whether rendered server-side or written via innerHTML.
    # Must match the marker-namespaced global that BrowserManager.check_execution reads.
    return f"<img src=x onerror=\"window['__hx_{marker}']=1\">"


@register
class StoredXssScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "xss"

    def _review_urls(self, ctx: ScanContext, forms: list) -> list[str]:
        # Prioritize each form's own page + the target (where stored content is
        # most likely rendered), then other HTML pages - before the cap.
        priority = [f.url.split("#", 1)[0] for f in forms] + [ctx.config.target]
        others = [
            ep.url.split("#", 1)[0]
            for ep in ctx.endpoints
            if ep.method == HttpMethod.GET and (ep.content_type and "html" in ep.content_type)
        ]
        seen: set[str] = set()
        unique: list[str] = []
        for url in [*priority, *others]:
            if url not in seen and ctx.scope.is_allowed(url):
                seen.add(url)
                unique.append(url)
        return unique[:MAX_REVIEW_PAGES]

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        if ctx.browser is None:
            logger.debug("stored-xss: no browser engine; skipping")
            return

        forms = [
            ep
            for ep in ctx.endpoints
            if ep.method == HttpMethod.POST and ep.source == "form"
        ][:MAX_FORMS]
        if not forms:
            return
        review_urls = self._review_urls(ctx, forms)

        for form in forms:
            body_params = [p.name for p in form.params if p.location == ParamLocation.BODY]
            if not body_params:
                continue
            marker = "hsx" + secrets.token_hex(4)
            payload = _payload(marker)
            data = {name: payload for name in body_params}

            try:
                await ctx.http.post(form.url, data=data)
            except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
                logger.debug("stored-xss submit failed for %s: %s", form.url, exc)
                continue

            for url in review_urls:
                probe = await ctx.browser.check_execution(
                    url, marker, screenshot_name=f"storedxss-{marker}"
                )
                if probe.executed:
                    yield Finding(
                        vuln_type="xss",
                        title="Stored XSS",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        url=url,
                        parameter=", ".join(body_params),
                        param_location=ParamLocation.BODY,
                        description=(
                            f"A payload submitted to {urlsplit(form.url).path} persisted and "
                            f"executed when {url} was later rendered in the browser (proof via "
                            f"{probe.method}). Stored XSS affects every visitor of the page."
                        ),
                        remediation=(
                            "Output-encode stored user content on render, validate on input, and "
                            "apply a strict CSP. Never trust previously stored data."
                        ),
                        cwe="CWE-79",
                        scanner=SCANNER_NAME,
                        evidence=Evidence(
                            request_raw=f"POST {form.url}\n\n{data}",
                            screenshot_path=probe.screenshot_path,
                            notes=f"persisted payload executed on {url} via {probe.method}",
                        ),
                    )
                    break


__all__ = ["StoredXssScanner"]
