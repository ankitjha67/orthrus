"""Client-side taint scanner — browser-instrumented DOM source→sink tracing.

Drives the headless browser's taint instrumentation (``BrowserManager.trace_taint``)
to find DOM-based vulnerabilities by *flow*, not just by execution: a unique
canary is seeded into the page URL (fragment + query) and the browser records any
DOM injection / navigation **sink** that receives a value carrying that canary.

This catches client-side bugs the server never sees — DOM XSS where attacker-
controlled URL data reaches ``eval`` / ``document.write`` / ``innerHTML`` /
``insertAdjacentHTML`` (CWE-79), and client-side open redirect where it reaches
``location.assign`` / ``location.replace`` / ``window.open`` (CWE-601) — and names
the exact sink in the finding. Browser-gated; no-ops without Playwright.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, HttpMethod, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.encoding import with_query_param

SCANNER_NAME = "dom-taint"
MAX_PAGES = 30

_XSS_SINKS = {
    "eval",
    "document.write",
    "document.writeln",
    "setTimeout",
    "setInterval",
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
}
_REDIRECT_SINKS = {"window.open", "location.assign", "location.replace"}


def classify_sink(sink: str) -> tuple[str, Severity, str] | None:
    """Map a JS sink name to (vuln_type, severity, cwe)."""
    if sink in _XSS_SINKS:
        return ("xss", Severity.HIGH, "CWE-79")
    if sink in _REDIRECT_SINKS:
        return ("open-redirect", Severity.MEDIUM, "CWE-601")
    return None


@register
class DomTaintScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "xss"

    def _pages(self, ctx: ScanContext) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()
        candidates = [ctx.config.target]
        candidates += [
            ep.url for ep in ctx.endpoints if ep.method in (HttpMethod.GET, HttpMethod.HEAD)
        ]
        for candidate in candidates:
            base = candidate.split("#", 1)[0]
            parts = urlsplit(base)
            if not parts.scheme:
                continue
            key = (parts.netloc, parts.path)
            if key in seen:
                continue
            seen.add(key)
            urls.append(base)
        return urls[:MAX_PAGES]

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        if ctx.browser is None:
            return
        for base in self._pages(ctx):
            if not ctx.scope.is_allowed(base):
                continue
            canary = "orthrustaint" + secrets.token_hex(4)
            seeded = with_query_param(base, "orthrustaint", canary) + "#" + canary
            flows = await ctx.browser.trace_taint(seeded)

            emitted: set[str] = set()
            for flow in flows:
                sink = str(flow.get("sink", ""))
                if sink in emitted:
                    continue
                classified = classify_sink(sink)
                if classified is None:
                    continue
                emitted.add(sink)
                vuln_type, severity, cwe = classified
                yield self._finding(base, sink, vuln_type, severity, cwe)

    def _finding(
        self, url: str, sink: str, vuln_type: str, severity: Severity, cwe: str
    ) -> Finding:
        if vuln_type == "xss":
            title = f"DOM-based XSS: URL-controlled value flows into {sink}()"
            desc = (
                f"A value taken from the page URL reached the JavaScript sink '{sink}', which "
                "renders/executes its argument. Attacker-controlled URL data flowing into this "
                "sink is DOM-based cross-site scripting — exploited entirely client-side, so the "
                "server (and server-side filters) never see the payload."
            )
            remediation = (
                "Never pass URL-derived data to HTML/script sinks. Use textContent / safe DOM "
                "APIs, sanitise with a vetted library (DOMPurify), and adopt Trusted Types + a "
                "strict CSP to neutralise DOM-XSS sinks."
            )
        else:
            title = f"Client-side open redirect: URL-controlled value flows into {sink}()"
            desc = (
                f"A value taken from the page URL reached the navigation sink '{sink}', so an "
                "attacker can craft a link on this page that redirects the victim to an arbitrary "
                "site (phishing / token theft) — entirely client-side."
            )
            remediation = (
                "Validate URL-derived navigation targets against an allow-list of same-origin / "
                "trusted destinations before assigning them to a navigation sink."
            )
        return Finding(
            vuln_type=vuln_type,
            title=title,
            severity=severity,
            confidence=Confidence.FIRM,
            url=url,
            description=desc,
            remediation=remediation,
            cwe=cwe,
            scanner=SCANNER_NAME,
            evidence=Evidence(
                matched_at=sink,
                notes=f"browser taint flow: URL canary reached {sink}",
            ),
        )


__all__ = ["DomTaintScanner", "classify_sink"]
