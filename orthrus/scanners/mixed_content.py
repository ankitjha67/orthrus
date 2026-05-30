"""Mixed-content / insecure-transport reference scanner (CWE-319).

An HTTPS page that pulls in resources over plain ``http://`` — or, far worse,
posts a form to an ``http://`` action — breaks the transport guarantee: an
on-path attacker can read or tamper with the insecure sub-request. A form whose
``action`` is ``http://`` leaks whatever the user submits (credentials, tokens)
in cleartext, so it is treated as HIGH; passive sub-resources (scripts, iframes,
images, styles) are MEDIUM/LOW.

Passive: parses the HTML of already-discovered HTTPS pages; no extra payloads.
Only flags ``http://`` references on ``https://`` pages (relative/protocol-
relative URLs and the page's own origin are ignored), so it never fires on a
plain-HTTP site or on secure references.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.mixed-content")

SCANNER_NAME = "mixed-content"
MAX_PAGES = 30

# (attribute, html tag/context, severity, label) — form actions are the worst.
_ACTIVE_RE = re.compile(r"""<form\b[^>]*\baction\s*=\s*['"]?(http://[^'"\s>]+)""", re.IGNORECASE)
_RESOURCE_RE = re.compile(
    r"""<(?:script|iframe|link|img|source|audio|video|embed|object)\b[^>]*"""
    r"""(?:src|href|data)\s*=\s*['"]?(http://[^'"\s>]+)""",
    re.IGNORECASE,
)


def find_mixed_content(html: str, page_url: str) -> list[tuple[str, str, Severity]]:
    """Return (kind, insecure_url, severity) for http:// references on an https page.

    ``kind`` is "form-action" (HIGH — submitted data leaks in cleartext) or
    "resource" (MEDIUM). Returns [] for non-HTTPS pages.
    """
    if urlsplit(page_url).scheme != "https":
        return []
    found: list[tuple[str, str, Severity]] = []
    seen: set[str] = set()
    for url in _ACTIVE_RE.findall(html or ""):
        if url not in seen:
            seen.add(url)
            found.append(("form-action", url, Severity.HIGH))
    for url in _RESOURCE_RE.findall(html or ""):
        if url not in seen:
            seen.add(url)
            found.append(("resource", url, Severity.MEDIUM))
    return found


@register
class MixedContentScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "mixed-content"

    def _https_pages(self, ctx: ScanContext) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()
        for candidate in (ctx.config.target, *[ep.url for ep in ctx.endpoints]):
            base = candidate.split("#", 1)[0]
            if urlsplit(base).scheme != "https":
                continue
            key = urlsplit(base).path or "/"
            if key in seen:
                continue
            seen.add(key)
            urls.append(base)
        return urls[:MAX_PAGES]

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        emitted: set[tuple[str, str]] = set()
        for url in self._https_pages(ctx):
            if not ctx.scope.is_allowed(url):
                continue
            try:
                resp = await ctx.http.get(url, follow_redirects=True)
            except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
                logger.debug("mixed-content fetch failed for %s: %s", url, exc)
                continue
            ctype = resp.headers.get("content-type", "")
            if "html" not in ctype.lower() and "<form" not in resp.text.lower():
                continue
            for kind, insecure_url, severity in find_mixed_content(resp.text, str(resp.url)):
                key = (urlsplit(url).path, insecure_url)
                if key in emitted:
                    continue
                emitted.add(key)
                yield self._finding(url, kind, insecure_url, severity)

    def _finding(self, page_url: str, kind: str, insecure_url: str, severity: Severity) -> Finding:
        if kind == "form-action":
            title = "Form submits over insecure HTTP (mixed content)"
            desc = (
                f"An HTTPS page posts a form to an insecure http:// action ({insecure_url}). "
                "Everything the user submits — including credentials or tokens — is sent in "
                "cleartext and can be read or modified by an on-path attacker."
            )
        else:
            title = "Insecure (HTTP) sub-resource on an HTTPS page (mixed content)"
            desc = (
                f"An HTTPS page references an http:// sub-resource ({insecure_url}). An on-path "
                "attacker can tamper with it; active mixed content (scripts/iframes) can lead to "
                "full page compromise."
            )
        return Finding(
            vuln_type="mixed-content",
            title=title,
            severity=severity,
            confidence=Confidence.FIRM,
            url=page_url,
            description=desc,
            remediation=(
                "Serve every sub-resource and form action over https:// (or protocol-relative / "
                "relative URLs). Add a Content-Security-Policy with "
                "'upgrade-insecure-requests' and 'block-all-mixed-content'."
            ),
            cwe="CWE-319",
            scanner=SCANNER_NAME,
            evidence=Evidence(matched_at=insecure_url, notes=f"{kind} over http on an https page"),
        )


__all__ = ["MixedContentScanner", "find_mixed_content"]
