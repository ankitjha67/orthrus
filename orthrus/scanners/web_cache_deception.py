"""Web cache deception scanner.

Distinct from cache *poisoning*: here a dynamic, often authenticated page is
requested with a static-looking suffix (``/account/orthrus.css``). If the
application ignores the extra path segment and returns the **same sensitive
content**, a caching layer (CDN/proxy) that keys on the ``.css`` extension may
cache that response and serve another user's private data from it.

The probe is read-only: request the page, then request the same path with an
appended ``/<random>.css`` and compare. A finding requires the static-looking
URL to return the dynamic page *verbatim* (low false positives); cache
indicators on the deceptive response raise severity/confidence.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from urllib.parse import urlsplit, urlunsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.cache_poisoning import is_cacheable
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.web-cache-deception")

SCANNER_NAME = "web-cache-deception"
MAX_URLS = 30
_STATIC_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".map")


def looks_static(path: str) -> bool:
    return path.lower().endswith(_STATIC_EXT)


def deception_signal(
    base_status: int, base_body: str, deceptive_status: int, deceptive_body: str
) -> bool:
    """True if a static-looking URL returned the dynamic page verbatim."""
    if base_status != 200 or deceptive_status != 200:
        return False
    base = base_body.strip()
    deceptive = deceptive_body.strip()
    return bool(base) and base == deceptive


@register
class WebCacheDeceptionScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "web-cache-deception"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen: set[tuple[str, str]] = set()
        controls: dict[str, str | None] = {}
        candidates = [ctx.config.target, *[ep.url for ep in ctx.endpoints]]
        tested = 0

        for url in candidates:
            if tested >= MAX_URLS:
                break
            parts = urlsplit(url.split("#", 1)[0])
            path = parts.path
            if not parts.netloc or path in ("", "/") or looks_static(path):
                continue
            key = (parts.netloc, path)
            if key in seen or not ctx.scope.is_allowed(url):
                continue
            seen.add(key)
            tested += 1

            base = await self._get(ctx, url)
            if base is None or base.status_code != 200:
                continue
            # Suppress soft-404 / catch-all sites: if this page equals the response
            # to a random bogus path on the same host, it isn't a distinct page and
            # the verbatim match means nothing.
            control = await self._control_body(ctx, parts, controls)
            if control is not None and base.text.strip() == control.strip():
                continue
            nonce = secrets.token_hex(3)
            dec_path = path.rstrip("/") + f"/orthrus-wcd-{nonce}.css"
            dec_url = urlunsplit((parts.scheme, parts.netloc, dec_path, "", ""))
            if not ctx.scope.is_allowed(dec_url):
                continue
            dec = await self._get(ctx, dec_url)
            if dec is None or not deception_signal(
                base.status_code, base.text, dec.status_code, dec.text
            ):
                continue

            cacheable = is_cacheable(dict(dec.headers))
            yield Finding(
                vuln_type="web-cache-deception",
                title=f"Web cache deception: dynamic page served at a static URL ({dec_path})",
                severity=Severity.MEDIUM if cacheable else Severity.LOW,
                confidence=Confidence.FIRM if cacheable else Confidence.TENTATIVE,
                url=dec_url,
                description=(
                    f"Appending '/<file>.css' to {path} returned the original dynamic page "
                    "verbatim instead of a 404. A CDN or proxy that caches by file extension can "
                    "then store this 'static' response and serve one user's private content to "
                    f"others.{' The response carries cache indicators.' if cacheable else ''}"
                ),
                remediation=(
                    "Make the origin return 404 for unknown sub-paths of dynamic routes; configure "
                    "the cache to key on the full normalized path and never cache responses that set "
                    "cookies or vary by session, regardless of the URL's apparent extension."
                ),
                cwe="CWE-525",
                scanner=SCANNER_NAME,
                evidence=Evidence(
                    request_raw=f"GET {dec_path}",
                    matched_at=dec_path,
                    notes="static-suffixed URL returned the dynamic page verbatim"
                    + (" (cacheable)" if cacheable else ""),
                ),
            )

    async def _control_body(
        self, ctx: ScanContext, parts: object, controls: dict[str, str | None]
    ) -> str | None:
        """Body of a random bogus path on this host (cached), or None.

        Only treated as a catch-all signal when it returns 200 - a distinct 404
        page means the host does not blanket-200, so no suppression is needed.
        """
        netloc = parts.netloc  # type: ignore[attr-defined]
        if netloc not in controls:
            ctrl_url = urlunsplit(
                (parts.scheme, netloc, f"/orthrus-wcd-control-{secrets.token_hex(3)}", "", "")  # type: ignore[attr-defined]
            )
            resp = await self._get(ctx, ctrl_url) if ctx.scope.is_allowed(ctrl_url) else None
            controls[netloc] = resp.text if resp is not None and resp.status_code == 200 else None
        return controls[netloc]

    async def _get(self, ctx: ScanContext, url: str) -> httpx.Response | None:
        try:
            return await ctx.http.get(url, follow_redirects=False)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("web-cache-deception probe failed for %s: %s", url, exc)
            return None


__all__ = ["WebCacheDeceptionScanner", "looks_static", "deception_signal"]
