"""Source-map recovery — reconstruct endpoints from leaked ``.map`` files.

Production front-ends are minified, but teams routinely ship the matching
JavaScript **source maps** (``//# sourceMappingURL=app.js.map``) to prod. A map's
``sourcesContent`` is the *original*, un-minified source — which exposes API
routes, internal paths, and constants that the minified bundle hides. Recovering
and mining it is one of the highest finding-density, lowest-cost recon moves.

This module locates the source map for each discovered JS file (from the inline
``sourceMappingURL`` comment, falling back to ``<file>.js.map``), fetches it
in-scope, parses ``sourcesContent``, and re-uses the JS endpoint extractor to
surface API endpoints from the original source — expanding the attack surface
for the scan phase. Read-only; every URL is scope-checked.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from urllib.parse import urljoin

import httpx

from orthrus.core import schemas
from orthrus.core.context import ScanContext
from orthrus.core.schemas import Endpoint, HttpMethod
from orthrus.recon.base import BaseRecon
from orthrus.recon.js_analyzer import extract_endpoints
from orthrus.recon.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("recon.sourcemap")

MAX_JS = 30
MAX_MAPS = 30

_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")


def sourcemap_url(js_body: str, js_url: str) -> str | None:
    """Return the absolute source-map URL referenced by a JS file, else None.

    Ignores inline ``data:`` maps (nothing to fetch) and resolves a relative
    reference against the JS file's URL. The last reference wins (bundlers emit
    the active map last).
    """
    matches = _SOURCEMAP_RE.findall(js_body or "")
    if not matches:
        return None
    ref = matches[-1].strip()
    if ref.startswith("data:"):
        return None
    return urljoin(js_url, ref)


def parse_sourcemap(text: str) -> tuple[list[str], list[str]]:
    """Return (sources, sourcesContent) from a source-map JSON document."""
    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        return [], []
    if not isinstance(doc, dict):
        return [], []
    sources = [s for s in doc.get("sources", []) if isinstance(s, str)]
    content = [c for c in doc.get("sourcesContent", []) if isinstance(c, str)]
    return sources, content


def endpoints_from_sourcemap(text: str, base_url: str) -> set[str]:
    """Mine endpoint URLs from the original source recovered in a source map."""
    _, content = parse_sourcemap(text)
    found: set[str] = set()
    for chunk in content:
        found.update(extract_endpoints(chunk, base_url))
    return found


@register
class SourceMapRecovery(BaseRecon):
    name = "sourcemap-recovery"

    async def discover(self, ctx: ScanContext) -> AsyncIterator[schemas.Endpoint]:
        js_endpoints = [
            ep
            for ep in ctx.endpoints
            if ep.source == "script" or ep.url.split("?", 1)[0].lower().endswith(".js")
        ]
        seen_js: set[str] = set()
        seen_maps: set[str] = set()
        emitted: set[str] = set()
        maps_fetched = 0

        for ep in js_endpoints[:MAX_JS]:
            if ep.url in seen_js or not ctx.scope.is_allowed(ep.url):
                continue
            seen_js.add(ep.url)

            js_body = await self._get(ctx, ep.url)
            if js_body is None:
                continue

            map_url = sourcemap_url(js_body, ep.url) or (ep.url.split("?", 1)[0] + ".map")
            if map_url in seen_maps or not ctx.scope.is_allowed(map_url) or maps_fetched >= MAX_MAPS:
                continue
            seen_maps.add(map_url)

            map_text = await self._get(ctx, map_url)
            if map_text is None or '"sources"' not in map_text:
                continue
            maps_fetched += 1
            sources, _ = parse_sourcemap(map_text)
            logger.info(
                "recovered source map %s (%d original sources)", map_url, len(sources)
            )

            for url in endpoints_from_sourcemap(map_text, ep.url):
                if url in emitted or not ctx.scope.is_allowed(url):
                    continue
                emitted.add(url)
                yield Endpoint(url=url, method=HttpMethod.GET, source="sourcemap")

    async def _get(self, ctx: ScanContext, url: str) -> str | None:
        try:
            resp = await ctx.http.get(url)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL):
            return None
        if resp.status_code != 200:
            return None
        return resp.text


__all__ = [
    "SourceMapRecovery",
    "sourcemap_url",
    "parse_sourcemap",
    "endpoints_from_sourcemap",
]
