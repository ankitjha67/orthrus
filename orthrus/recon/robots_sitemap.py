"""robots.txt + sitemap endpoint discovery.

Two of the highest-signal, lowest-noise recon sources on a web target:

* **robots.txt** — its ``Disallow``/``Allow`` directives enumerate exactly the
  paths an admin *didn't* want crawled (admin panels, exports, staging), and its
  ``Sitemap:`` lines point at the sitemaps.
* **sitemap.xml** — a machine-readable list of the site's real URLs, including a
  ``<sitemapindex>`` that fans out to more sitemaps; gzipped (``.xml.gz``) variants
  are handled.

Both are fetched through the scope-enforced ``ctx.http`` and every discovered URL
is scope-checked before it's yielded. Sitemaps are parsed with a ``<loc>`` regex
rather than an XML parser **on purpose** — the document is attacker-controlled, so
we never feed it to an entity-expanding parser (no self-inflicted XXE). The pure
``parse_robots`` / ``parse_sitemap`` helpers are unit-tested.
"""

from __future__ import annotations

import gzip
import re
from collections.abc import AsyncIterator
from urllib.parse import urljoin, urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Endpoint, HttpMethod
from orthrus.recon.base import BaseRecon
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("recon.robots_sitemap")

_LOC_RE = re.compile(r"<loc>\s*([^<\s][^<]*?)\s*</loc>", re.IGNORECASE | re.DOTALL)
_MAX_SITEMAPS = 25  # fetch cap (index fan-out guard)
_MAX_URLS = 500  # endpoint cap


def _base_url(target: str) -> str:
    parts = urlsplit(target if "://" in target else f"//{target}")
    scheme = parts.scheme or "http"
    return f"{scheme}://{parts.netloc}"


def parse_robots(text: str) -> tuple[list[str], list[str]]:
    """Parse robots.txt → (concrete Disallow/Allow paths, Sitemap URLs)."""
    paths: list[str] = []
    sitemaps: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        field, _, value = line.partition(":")
        field = field.strip().lower()
        value = value.strip()
        if not value:
            continue
        if field in ("disallow", "allow"):
            # Concrete, requestable paths only — skip site-wide "/" and wildcards.
            if value.startswith("/") and value not in ("/", "/*") and "*" not in value:
                paths.append(value)
        elif field == "sitemap" and value.startswith(("http://", "https://")):
            sitemaps.append(value)
    return list(dict.fromkeys(paths)), list(dict.fromkeys(sitemaps))


def parse_sitemap(text: str) -> tuple[list[str], bool]:
    """Parse a sitemap → (loc URLs, is_index). Regex-based (no XML parser on hostile input)."""
    locs = [
        m.group(1).strip()
        for m in _LOC_RE.finditer(text)
        if m.group(1).strip().startswith(("http://", "https://"))
    ]
    is_index = "<sitemapindex" in text.lower()
    return list(dict.fromkeys(locs)), is_index


def _decode_sitemap(url: str, content: bytes) -> str:
    if url.lower().endswith(".gz") or content[:2] == b"\x1f\x8b":
        try:
            content = gzip.decompress(content)
        except OSError:
            return ""
    return content.decode("utf-8", "ignore")


class RobotsSitemap(BaseRecon):
    name = "robots-sitemap"

    async def discover(self, ctx: ScanContext) -> AsyncIterator[Endpoint]:
        base = _base_url(ctx.config.target)
        seen: set[str] = set()
        sitemap_queue: list[str] = []

        # --- robots.txt ---
        robots_url = f"{base}/robots.txt"
        if ctx.scope.is_allowed(robots_url):
            try:
                resp = await ctx.http.get(robots_url, follow_redirects=True)
                ctype = resp.headers.get("content-type", "")
                if resp.status_code == 200 and "html" not in ctype.lower():
                    paths, sitemaps = parse_robots(resp.text)
                    sitemap_queue.extend(sitemaps)
                    for path in paths:
                        url = urljoin(f"{base}/", path)
                        if url not in seen and ctx.scope.is_allowed(url):
                            seen.add(url)
                            yield Endpoint(url=url, method=HttpMethod.GET, source="robots")
            except (ScopeViolation, httpx.HTTPError) as exc:
                logger.debug("robots.txt fetch failed: %s", exc)

        # --- sitemaps (robots-declared + the conventional default), one index level ---
        sitemap_queue.append(f"{base}/sitemap.xml")
        queue = list(dict.fromkeys(sitemap_queue))
        fetched: set[str] = set()
        url_count = 0
        while queue and len(fetched) < _MAX_SITEMAPS and url_count < _MAX_URLS:
            sm = queue.pop(0)
            if sm in fetched or not ctx.scope.is_allowed(sm):
                continue
            fetched.add(sm)
            try:
                resp = await ctx.http.get(sm, follow_redirects=True)
            except (ScopeViolation, httpx.HTTPError) as exc:
                logger.debug("sitemap fetch failed (%s): %s", sm, exc)
                continue
            if resp.status_code != 200:
                continue
            locs, is_index = parse_sitemap(_decode_sitemap(sm, resp.content))
            if is_index:
                for loc in locs:
                    if loc not in fetched and len(fetched) + len(queue) < _MAX_SITEMAPS:
                        queue.append(loc)
                continue
            for loc in locs:
                if url_count >= _MAX_URLS:
                    break
                if loc not in seen and ctx.scope.is_allowed(loc):
                    seen.add(loc)
                    url_count += 1
                    yield Endpoint(url=loc, method=HttpMethod.GET, source="sitemap")


__all__ = ["RobotsSitemap", "parse_robots", "parse_sitemap"]
