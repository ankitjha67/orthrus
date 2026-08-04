"""Static deep web crawler (PRD §5.2).

Hybrid crawling is a roadmap goal; this is the httpx-based static half. It does
breadth-first discovery within scope, extracts links and forms, dedupes by URL
and content hash, and yields Endpoint objects. The Playwright dynamic half
(JS-rendered DOM, SPA routes) plugs in behind the same BaseRecon interface.
"""

from __future__ import annotations

import hashlib
from collections import deque
from collections.abc import AsyncIterator
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from bs4 import BeautifulSoup

from orthrus.core import schemas
from orthrus.core.context import ScanContext
from orthrus.core.schemas import Endpoint, HttpMethod, Param, ParamLocation
from orthrus.recon.base import BaseRecon
from orthrus.recon.js_analyzer import extract_endpoints, extract_websockets, params_from_query
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("recon.crawler")

_SKIP_SCHEMES = {"mailto", "tel", "javascript", "data", "ftp", "file"}
_NON_PARSEABLE = ("application/pdf", "image/", "video/", "audio/", "font/")


def _normalize(url: str) -> str | None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return None
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def _content_hash(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest()


def _parse_form(page_url: str, form: object) -> Endpoint:
    action = form.get("action") or ""  # type: ignore[attr-defined]
    method_str = (form.get("method") or "GET").upper()  # type: ignore[attr-defined]
    method = HttpMethod.POST if method_str == "POST" else HttpMethod.GET
    target_url = _normalize(urljoin(page_url, action)) or page_url

    location = ParamLocation.BODY if method == HttpMethod.POST else ParamLocation.QUERY
    params: list[Param] = []
    for field in form.find_all(["input", "textarea", "select"]):  # type: ignore[attr-defined]
        name = field.get("name")
        if not name:
            continue
        params.append(Param(name=name, location=location, value=field.get("value")))

    return Endpoint(url=target_url, method=method, params=params, source="form")


class Crawler(BaseRecon):
    name = "crawler"

    async def discover(self, ctx: ScanContext) -> AsyncIterator[schemas.Endpoint]:
        start = _normalize(ctx.config.target) or ctx.config.target
        max_depth = ctx.config.crawl_depth
        max_pages = ctx.config.max_pages

        seen_urls: set[str] = set()
        seen_hashes: set[str] = set()
        # (path, sorted-param-names) already surfaced as a query-bearing endpoint,
        # so five `/catalog?category=<X>` links collapse to one injection point
        # instead of five near-duplicate endpoints.
        seen_param_eps: set[tuple[str, tuple[str, ...]]] = set()
        queue: deque[tuple[str, int]] = deque([(start, 0)])
        pages = 0

        while queue and pages < max_pages:
            url, depth = queue.popleft()
            if url in seen_urls:
                continue
            seen_urls.add(url)
            if not ctx.scope.is_allowed(url):
                continue

            try:
                resp = await ctx.http.get(url)
            except ScopeViolation:
                continue
            except httpx.HTTPError as exc:
                logger.debug("crawl fetch failed for %s: %s", url, exc)
                continue

            pages += 1
            content_type = resp.headers.get("content-type", "")
            is_html = "html" in content_type
            body = resp.text if is_html or "text" in content_type else ""

            yield Endpoint(
                url=url,
                method=HttpMethod.GET,
                params=params_from_query(url),
                response_status=resp.status_code,
                response_headers=dict(resp.headers),
                set_cookies=resp.headers.get_list("set-cookie"),
                content_type=content_type or None,
                content_length=len(resp.content),
                content_hash=_content_hash(body) if body else None,
                source="crawler",
            )

            if not is_html or any(np in content_type for np in _NON_PARSEABLE):
                continue

            chash = _content_hash(body)
            if chash in seen_hashes:
                continue  # identical page already mined for links/forms
            seen_hashes.add(chash)

            soup = BeautifulSoup(body, "lxml")

            for form in soup.find_all("form"):
                yield _parse_form(url, form)

            # External scripts -> recorded for the JS analyzer to fetch.
            for script in soup.find_all("script", src=True):
                src = _normalize(urljoin(url, script["src"].strip()))
                if src and src not in seen_urls and ctx.scope.is_allowed(src):
                    seen_urls.add(src)
                    yield Endpoint(url=src, method=HttpMethod.GET, source="script")

            # Inline scripts -> mine endpoints / websockets directly (body in hand).
            # SPA filter links (e.g. a React `{"Gin":"/catalog?category=Gin"}`
            # map) live here, not in <a href> anchors, so this is often the only
            # place their injectable query params can be recovered.
            for script in soup.find_all("script", src=False):
                code = script.string or script.get_text() or ""
                if not code.strip():
                    continue
                for ep_url in extract_endpoints(code, url):
                    if not ctx.scope.is_allowed(ep_url):
                        continue
                    ep_params = params_from_query(ep_url)
                    if ep_params:
                        key = (urlsplit(ep_url).path, tuple(sorted(p.name for p in ep_params)))
                        if key in seen_param_eps:
                            continue
                        seen_param_eps.add(key)
                    yield Endpoint(
                        url=ep_url, method=HttpMethod.GET, params=ep_params, source="js-inline"
                    )
                for ws in extract_websockets(code, url):
                    if ws not in ctx.websockets:
                        ctx.websockets.append(ws)

            for anchor in soup.find_all("a", href=True):
                href = anchor["href"].strip()
                if urlsplit(href).scheme.lower() in _SKIP_SCHEMES:
                    continue
                child = _normalize(urljoin(url, href))
                if not child or not ctx.scope.is_allowed(child):
                    continue
                if depth < max_depth:
                    if child not in seen_urls:
                        queue.append((child, depth + 1))
                    continue
                # At the depth frontier we stop crawling, but a link that still
                # carries a `?a=b` query is an injection point in its own right -
                # harvest it (deduped by path + param-set) rather than dropping the
                # parameter on the floor.
                child_params = params_from_query(child)
                if not child_params:
                    continue
                key = (urlsplit(child).path, tuple(sorted(p.name for p in child_params)))
                if key not in seen_param_eps:
                    seen_param_eps.add(key)
                    yield Endpoint(
                        url=child, method=HttpMethod.GET, params=child_params, source="crawler-link"
                    )


__all__ = ["Crawler"]
