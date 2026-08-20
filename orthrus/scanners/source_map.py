"""JavaScript source-map exposure scanner (original-source disclosure).

Production sites routinely deploy ``.js.map`` files next to their minified
bundles. A source map with a populated ``sourcesContent`` array embeds the
**original, un-minified source** - reconstructable verbatim with a one-liner -
exposing internal module names, backend route strings, comments, feature flags,
and not-infrequently hard-coded secrets. Even without ``sourcesContent``, the
``sources`` path list leaks the app's internal directory structure.

For every discovered ``.js`` asset this probes the conventional ``<bundle>.map``
location (and parses a ``.map`` the crawler already found), parsing the JSON to
distinguish full-source reconstruction (HIGH) from path-only disclosure (MEDIUM).
Deterministic - a valid source-map JSON with sources is the signal.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, HttpMethod, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.source-map")

SCANNER_NAME = "source-map-exposure"
MAX_TARGETS = 30


def parse_source_map(text: str) -> dict | None:
    """Return {sources, has_content, sample} for a valid source map, else None."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict) or "version" not in data or "sources" not in data:
        return None
    sources = [s for s in (data.get("sources") or []) if isinstance(s, str)]
    contents = data.get("sourcesContent") or []
    has_content = any(isinstance(c, str) and c.strip() for c in contents)
    if not sources and not has_content:
        return None
    return {"sources": sources, "has_content": has_content, "sample": sources[:5]}


def _base(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


@register
class SourceMapScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "source-map-exposure"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        tested = 0
        for ep in ctx.endpoints:
            if ep.method != HttpMethod.GET:
                continue
            base = _base(ep.url)
            low = base.lower()
            if low.endswith(".map"):
                map_url = base
            elif low.endswith(".js"):
                map_url = base + ".map"
            else:
                continue
            if map_url in seen or not ctx.scope.is_allowed(map_url):
                continue
            seen.add(map_url)
            if tested >= MAX_TARGETS:
                break
            tested += 1

            resp = await self._get(ctx, map_url)
            if resp is None or resp.status_code != 200:
                continue
            parsed = parse_source_map(resp.text)
            if parsed is not None:
                yield self._finding(map_url, parsed)

    async def _get(self, ctx: ScanContext, url: str) -> httpx.Response | None:
        try:
            return await ctx.http.get(url, follow_redirects=True)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("source-map probe failed for %s: %s", url, exc)
            return None

    def _finding(self, url: str, parsed: dict) -> Finding:
        has_content = parsed["has_content"]
        n = len(parsed["sources"])
        sample = ", ".join(parsed["sample"]) or "(none)"
        if has_content:
            sev, what = Severity.HIGH, "with full original source embedded (sourcesContent)"
        else:
            sev, what = Severity.MEDIUM, "exposing the internal source-file path list"
        return Finding(
            vuln_type="source-map-exposure",
            title=f"Exposed JavaScript source map ({urlsplit(url).path})",
            severity=sev,
            confidence=Confidence.FIRM,
            url=url,
            description=(
                f"A JavaScript source map is publicly reachable at {url} {what}. It references "
                f"{n} original source file(s) (e.g. {sample}). Source maps reconstruct the "
                "un-minified application source - internal module names, backend route strings, "
                "comments, feature flags, and sometimes hard-coded secrets - handing an attacker a "
                "white-box view of the client and a map of the API surface."
            ),
            remediation=(
                "Do not deploy .map files to production (or restrict them by network/auth), and "
                "strip the 'sourceMappingURL' comment from shipped bundles. If maps are needed for "
                "error monitoring, upload them privately to the monitoring service instead."
            ),
            cwe="CWE-540",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                matched_at=urlsplit(url).path,
                notes=f"valid source map, {n} sources, sourcesContent={'present' if has_content else 'absent'}",
            ),
        )


__all__ = ["SourceMapScanner", "parse_source_map"]
