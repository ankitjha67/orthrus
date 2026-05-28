"""Wayback Machine historical endpoint discovery (PRD §4.3.4).

Queries the Internet Archive CDX API (free, no key) for historically observed
URLs on the target domain and yields the in-scope ones as endpoints. Pure
``parse_wayback`` is unit-tested.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from hydra.core import schemas
from hydra.core.context import ScanContext
from hydra.core.schemas import Endpoint, HttpMethod
from hydra.recon.base import BaseRecon
from hydra.utils.logger import get_logger

logger = get_logger("recon.wayback")

CDX_API = "http://web.archive.org/cdx/search/cdx"
MAX_RESULTS = 500


def parse_wayback(rows: list[list[str]]) -> list[str]:
    """CDX JSON is a list of rows; row[0] is the header. Extract original URLs."""
    urls: list[str] = []
    for row in rows[1:] if rows else []:
        if row and isinstance(row, list):
            url = row[0].split("#", 1)[0]
            if url.startswith(("http://", "https://")):
                urls.append(url)
    return list(dict.fromkeys(urls))


class Wayback(BaseRecon):
    name = "wayback"

    async def discover(self, ctx: ScanContext) -> AsyncIterator[schemas.Endpoint]:
        target = ctx.config.target
        host = (urlsplit(target if "://" in target else f"//{target}").hostname or target).lower()
        params = {
            "url": f"{host}/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": MAX_RESULTS,
        }
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(CDX_API, params=params)
                rows = resp.json() if resp.status_code == 200 else []
        except (httpx.HTTPError, ValueError) as exc:
            logger.debug("wayback query failed: %s", exc)
            return

        seen: set[str] = set()
        for url in parse_wayback(rows):
            norm = url.split("#", 1)[0]
            if norm in seen or not ctx.scope.is_allowed(norm):
                continue
            seen.add(norm)
            yield Endpoint(url=norm, method=HttpMethod.GET, source="wayback")


__all__ = ["Wayback", "parse_wayback"]
