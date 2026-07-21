"""SPA client-side route discovery - deep dynamic recon (PRD §5.2).

`browser-crawl` drives the target's entry page so its bootstrap XHR/fetch calls
are captured. But a modern single-page app (React Router / Angular Router / Vue
Router) keeps most of its attack surface behind *client-side routes* that never
trigger a server navigation - ``/#/administration``, ``/orders/42``, lazy-loaded
feature modules. Each route, once rendered, fires its own route-specific API
calls. This module enumerates those routes from the rendered DOM (anchor hrefs,
Angular ``routerLink``, Vue ``to``, ``data-*`` nav hints, hash fragments), then
navigates each in the headless browser so the SPA's lazy/state-dependent
requests fire and are captured as Endpoints.

It runs only when the browser engine is available, and every route navigation
and captured request is still bound by the scope validator.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urljoin, urlsplit

from orthrus.core import schemas
from orthrus.core.context import ScanContext
from orthrus.recon.base import BaseRecon
from orthrus.recon.browser_crawl import endpoint_from_capture
from orthrus.utils.logger import get_logger

logger = get_logger("recon.spa-crawl")

MAX_ROUTES = 25  # client-side routes to drive (bounds runtime)
NAV_WAIT_MS = 1200  # let each route's lazy XHR/fetch fire after navigation

# JS harvested from the rendered DOM: every declarative navigation target a
# framework router exposes. Rendered <router-link>/<a routerLink> become real
# anchors, but we also read the source attributes for routers that defer render.
_ROUTE_HARVEST_JS = """() => {
  const out = [];
  const push = (v) => { if (v) out.push(v); };
  for (const a of document.querySelectorAll('a[href]')) push(a.getAttribute('href'));
  for (const el of document.querySelectorAll('[routerLink]')) push(el.getAttribute('routerLink'));
  for (const el of document.querySelectorAll('[ng-reflect-router-link]'))
    push(el.getAttribute('ng-reflect-router-link'));
  for (const el of document.querySelectorAll('[to]')) push(el.getAttribute('to'));
  for (const el of document.querySelectorAll('[data-href],[data-route],[data-path]'))
    push(el.getAttribute('data-href') || el.getAttribute('data-route')
         || el.getAttribute('data-path'));
  return Array.from(new Set(out)).slice(0, 400);
}"""


def _resolve_route(base: str, href: str) -> str | None:
    """Resolve a raw nav target against the SPA base URL to an http(s) URL.

    Handles relative paths, absolute URLs and hash routes; rejects
    ``javascript:``/``mailto:``/empty and non-http schemes.
    """
    href = (href or "").strip()
    if not href or href == "#":
        return None
    if href.lower().startswith(("javascript:", "mailto:", "tel:", "data:", "blob:")):
        return None
    abs_url = urljoin(base, href)
    parts = urlsplit(abs_url)
    if parts.scheme not in ("http", "https"):
        return None
    return abs_url


class SpaCrawl(BaseRecon):
    name = "spa-routes"

    def applicable(self, ctx: ScanContext) -> bool:
        return ctx.browser is not None

    async def discover(self, ctx: ScanContext) -> AsyncIterator[schemas.Endpoint]:
        browser = ctx.browser
        assert browser is not None

        base = ctx.config.target
        base_parts = urlsplit(base)
        shell_key = (base_parts.netloc, base_parts.path or "/")

        raw = await browser.evaluate_on(base, _ROUTE_HARVEST_JS, wait_ms=NAV_WAIT_MS)
        candidates = [c for c in (raw or []) if isinstance(c, str)]

        routes: list[str] = []
        seen: set[str] = set()
        for href in candidates:
            url = _resolve_route(base, href)
            if url is None or url in seen:
                continue
            seen.add(url)
            if not ctx.scope.is_allowed(url):
                continue
            parts = urlsplit(url)
            # Skip the bare shell page (same path, no client-side route fragment)
            # - browser-crawl already drove it; only deeper routes are new.
            if not parts.fragment and (parts.netloc, parts.path or "/") == shell_key:
                continue
            routes.append(url)
            if len(routes) >= MAX_ROUTES:
                break

        # Only the API calls triggered by *our* route navigation are new surface;
        # everything before this index was already harvested by browser-crawl.
        start_index = len(browser.captured)
        for url in routes:
            await browser.render(url, wait_ms=NAV_WAIT_MS)

        emitted: set[tuple[str, str]] = set()
        new_caps = browser.captured[start_index:]
        for cap in new_caps:
            ep = endpoint_from_capture(cap)
            if ep is None or not ctx.scope.is_allowed(ep.url):
                continue
            key = (ep.method.value, ep.url)
            if key in emitted:
                continue
            emitted.add(key)
            ep.source = "spa-routes"
            yield ep

        logger.info(
            "spa-routes: found %d client-side route(s), captured %d new API request(s)",
            len(routes),
            len(emitted),
        )


__all__ = ["SpaCrawl", "_resolve_route"]
