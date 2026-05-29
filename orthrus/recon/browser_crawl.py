"""Browser-driven dynamic crawl — the Playwright half of recon (PRD §5.2).

A static crawler only sees server-rendered HTML, so a single-page app's real
attack surface (its `/rest` and `/api` JSON calls) is invisible to it. This
module drives the target through the headless browser so the SPA's client-side
JS fires its actual XHR/fetch requests, which the browser engine records. Those
captured requests are converted into Endpoints — with JSON-body params — so the
scan phase can probe the JSON/REST API surface.

It runs only when the browser engine is available, and every navigation and
captured request is still bound by the scope validator.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from orthrus.core import schemas
from orthrus.core.browser import CapturedRequest
from orthrus.core.context import ScanContext
from orthrus.core.schemas import Endpoint, HttpMethod, Param, ParamLocation
from orthrus.recon.base import BaseRecon
from orthrus.utils.logger import get_logger

logger = get_logger("recon.browser-crawl")

MAX_NAV = 20  # pages to drive through the browser (bounds runtime)
NAV_WAIT_MS = 1500  # let the SPA's XHR/fetch fire after load

# Transport/polling traffic that isn't an application endpoint — excluding it
# avoids flooding the inventory with noise and false positives (e.g. an IDOR
# flagged on the Engine.IO protocol-version param).
_TRANSPORT_NOISE = ("/socket.io/", "/engine.io/")


def _normalize(url: str) -> str | None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return None
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def _stringify(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return json.dumps(value)  # nested object/array kept as a JSON string


def endpoint_from_capture(cap: CapturedRequest) -> Endpoint | None:
    """Convert a captured XHR/fetch request into an Endpoint with typed params.

    Query-string keys become QUERY params; a JSON body's top-level keys become
    JSON params; a urlencoded body's keys become BODY params.
    """
    url = _normalize(cap.url)
    if url is None:
        return None
    path = urlsplit(url).path
    if any(seg in path for seg in _TRANSPORT_NOISE):
        return None  # websocket transport polling, not an app endpoint
    try:
        method = HttpMethod(cap.method.upper())
    except ValueError:
        return None

    params: list[Param] = [
        Param(name=name, location=ParamLocation.QUERY, value=value)
        for name, value in parse_qsl(urlsplit(cap.url).query, keep_blank_values=True)
    ]

    ctype = (cap.content_type or "").lower()
    body = (cap.post_data or "").strip()
    if body:
        looks_json = "json" in ctype or body[:1] in ("{", "[")
        if looks_json:
            try:
                obj = json.loads(body)
            except ValueError:
                obj = None
            if isinstance(obj, dict):
                params.extend(
                    Param(name=str(k), location=ParamLocation.JSON, value=_stringify(v))
                    for k, v in obj.items()
                )
        elif "x-www-form-urlencoded" in ctype or "=" in body:
            params.extend(
                Param(name=n, location=ParamLocation.BODY, value=v)
                for n, v in parse_qsl(body, keep_blank_values=True)
            )

    return Endpoint(
        url=url,
        method=method,
        params=params,
        content_type=cap.content_type,
        source="browser",
    )


class BrowserCrawl(BaseRecon):
    name = "browser-crawl"

    def applicable(self, ctx: ScanContext) -> bool:
        return ctx.browser is not None

    async def discover(self, ctx: ScanContext) -> AsyncIterator[schemas.Endpoint]:
        browser = ctx.browser
        assert browser is not None

        # Drive the target + already-discovered in-scope GET pages so their JS
        # bootstraps and fires real API calls (captured at the context route).
        nav: list[str] = []
        seen: set[str] = set()
        candidates = [ctx.config.target, *(e.url for e in ctx.endpoints if e.method == HttpMethod.GET)]
        for raw in candidates:
            norm = _normalize(raw)
            if norm and norm not in seen and ctx.scope.is_allowed(norm):
                seen.add(norm)
                nav.append(norm)
            if len(nav) >= MAX_NAV:
                break

        for url in nav:
            await browser.render(url, wait_ms=NAV_WAIT_MS)

        # Harvest captured API requests into endpoints for the scan phase.
        emitted: set[tuple[str, str]] = set()
        captured = list(browser.captured)
        for cap in captured:
            ep = endpoint_from_capture(cap)
            if ep is None or not ctx.scope.is_allowed(ep.url):
                continue
            key = (ep.method.value, ep.url)
            if key in emitted:
                continue
            emitted.add(key)
            yield ep

        injectable = sum(
            1
            for cap in captured
            for ep in [endpoint_from_capture(cap)]
            if ep and ep.params
        )
        logger.info(
            "browser-crawl: navigated %d page(s), captured %d API request(s) (%d with params)",
            len(nav),
            len(captured),
            injectable,
        )


__all__ = ["BrowserCrawl", "endpoint_from_capture"]
