"""Subresource Integrity (SRI) scanner - CWE-353 (Missing Support for Integrity Check).

A page that pulls a third-party ``<script>`` or stylesheet from a CDN without an
``integrity=`` hash trusts that origin completely: if the CDN (or a dependency on
it) is compromised, attacker-controlled JavaScript runs with full page privileges.
This is the web-observable side of the supply-chain / Magecart and drive-by-download
threats - the classic "one compromised CDN becomes a breach across every site that
embeds it".

Passive: parses the HTML of already-discovered pages; sends no payloads. To stay
high-signal and avoid overlap with the mixed-content scanner it only flags
*third-party* resources (a different registrable domain) loaded over https:// or
protocol-relative URLs - same-origin assets and http:// resources are ignored.
The verdict logic (``find_missing_sri``) is pure and unit-tested.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from urllib.parse import urljoin, urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.sri")

SCANNER_NAME = "sri"
MAX_PAGES = 30

_TAG_RE = re.compile(r"<(script|link)\b([^>]*)>", re.IGNORECASE)
_ATTR_RE = re.compile(
    r"""([a-zA-Z][a-zA-Z0-9-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))"""
)


def _attrs(blob: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in _ATTR_RE.finditer(blob):
        out[m.group(1).lower()] = m.group(2) or m.group(3) or m.group(4) or ""
    return out


def _registrable(host: str) -> str:
    """Registrable domain via tldextract when available; else the last two labels."""
    host = host.lower()
    try:
        import tldextract

        reg = tldextract.extract(host).registered_domain
        if reg:
            return reg
    except Exception:
        pass
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def find_missing_sri(html: str, page_url: str) -> list[tuple[str, str, Severity]]:
    """Return (kind, resource_url, severity) for third-party resources lacking SRI.

    ``kind`` is "script" (MEDIUM - executes with page privileges) or "stylesheet"
    (LOW). Only cross-registrable-domain resources fetched over https:// (or
    protocol-relative) with no non-empty ``integrity`` attribute are returned.
    """
    page_host = urlsplit(page_url).hostname or ""
    if not page_host:
        return []
    page_reg = _registrable(page_host)
    found: list[tuple[str, str, Severity]] = []
    seen: set[str] = set()

    for tag, blob in _TAG_RE.findall(html or ""):
        tag = tag.lower()
        attrs = _attrs(blob)
        if tag == "script":
            ref = attrs.get("src", "")
            kind, severity = "script", Severity.MEDIUM
        else:  # link
            rel = attrs.get("rel", "").lower()
            if not any(r in rel for r in ("stylesheet", "preload", "modulepreload")):
                continue
            ref = attrs.get("href", "")
            kind, severity = "stylesheet", Severity.LOW
        if not ref:
            continue

        resolved = urljoin(page_url, ref)
        parts = urlsplit(resolved)
        if parts.scheme != "https" or not parts.hostname:
            continue  # http:// is mixed-content's job; skip data:/blob:/relative-same-origin
        if _registrable(parts.hostname) == page_reg:
            continue  # first-party asset - SRI is about third-party integrity
        if attrs.get("integrity", "").strip():
            continue  # already protected
        if resolved in seen:
            continue
        seen.add(resolved)
        found.append((kind, resolved, severity))

    return found


@register
class SriScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "sri"

    def _pages(self, ctx: ScanContext) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()
        for candidate in (ctx.config.target, *[ep.url for ep in ctx.endpoints]):
            base = candidate.split("#", 1)[0]
            if urlsplit(base).scheme not in ("http", "https"):
                continue
            key = (urlsplit(base).netloc, urlsplit(base).path or "/")
            if key in seen:
                continue
            seen.add(key)
            urls.append(base)
        return urls[:MAX_PAGES]

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        emitted: set[tuple[str, str]] = set()
        for url in self._pages(ctx):
            if not ctx.scope.is_allowed(url):
                continue
            try:
                resp = await ctx.http.get(url, follow_redirects=True)
            except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
                logger.debug("sri fetch failed for %s: %s", url, exc)
                continue
            if "html" not in resp.headers.get("content-type", "").lower():
                continue
            for kind, resource_url, severity in find_missing_sri(resp.text, str(resp.url)):
                key = (urlsplit(url).path, resource_url)
                if key in emitted:
                    continue
                emitted.add(key)
                yield self._finding(url, kind, resource_url, severity)

    def _finding(self, page_url: str, kind: str, resource_url: str, severity: Severity) -> Finding:
        host = urlsplit(resource_url).hostname or resource_url
        noun = "script" if kind == "script" else "stylesheet"
        consequence = (
            "attacker-controlled JavaScript would execute with the full privileges of this "
            "page (session tokens, DOM, form data)"
            if kind == "script"
            else "attacker-controlled CSS could deface the page or exfiltrate data via selectors"
        )
        return Finding(
            vuln_type="sri",
            title=f"Third-party {noun} loaded without Subresource Integrity",
            severity=severity,
            confidence=Confidence.FIRM,
            url=page_url,
            description=(
                f"The page includes a {noun} from a third-party origin ({host}) without an "
                f"integrity= hash. If that origin is compromised, {consequence}. This is the "
                "web-observable form of a supply-chain / CDN-compromise attack."
            ),
            remediation=(
                f"Add a Subresource Integrity hash (integrity=\"sha384-...\") and "
                f"crossorigin=\"anonymous\" to the {noun} tag, pinning a specific version, or "
                "self-host the resource. Consider a CSP require-sri-for directive."
            ),
            cwe="CWE-353",
            scanner=SCANNER_NAME,
            evidence=Evidence(matched_at=resource_url, notes=f"third-party {noun} without integrity="),
        )


__all__ = ["SriScanner", "find_missing_sri"]
