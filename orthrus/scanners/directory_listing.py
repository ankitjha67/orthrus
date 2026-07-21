"""Directory-listing / autoindex scanner (CWE-548).

When a web server (Apache ``mod_autoindex``, Nginx ``autoindex on``, IIS
directory browsing, or a framework dev server) serves a directory that has no
index file, it renders an auto-generated listing of the directory's contents.
That listing leaks file names, backups, source, and layout - handy
reconnaissance for an attacker.

This scanner builds a small set of candidate directory URLs from (a) the parent
directories of every discovered endpoint and (b) a curated common-directory
list, then GETs each (no redirects) and flags any ``200`` response whose body
carries a specific autoindex marker. A bare ``200`` never qualifies - only a
positive listing signal does, keeping false positives low.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit, urlunsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import (
    Aggressiveness,
    Confidence,
    Evidence,
    Finding,
    Severity,
)
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.directory-listing")

SCANNER_NAME = "directory-listing"
MAX_DIRS = 40

# Common directories that frequently have autoindex enabled.
COMMON_DIRS: tuple[str, ...] = (
    "/",
    "/uploads/",
    "/static/",
    "/files/",
    "/images/",
    "/backup/",
    "/assets/",
    "/media/",
)


def is_directory_listing(body: str) -> bool:
    """True if the body carries an autoindex/directory-listing marker.

    Matching is case-insensitive. A specific marker is required - a bare ``200``
    must never qualify.
    """
    low = body.lower()
    markers = (
        "index of /",
        "<title>index of",
        "directory listing for",
        "[to parent directory]",
    )
    if any(marker in low for marker in markers):
        return True
    # Apache/Nginx fallback: a "Parent Directory" link alongside file anchors.
    return "parent directory" in low and "<a href=" in low


def _dir_paths(path: str) -> list[str]:
    """Parent directory paths of an endpoint path (e.g. /a/b/c -> /a/b/, /a/)."""
    out: list[str] = []
    # Strip the final non-directory segment; keep walking up the tree.
    trimmed = path if path.endswith("/") else path.rsplit("/", 1)[0] + "/"
    while trimmed and trimmed != "/":
        if trimmed not in out:
            out.append(trimmed)
        trimmed = trimmed.rstrip("/").rsplit("/", 1)[0] + "/"
    return out


def candidate_dirs(target: str, endpoint_urls: list[str]) -> list[str]:
    """Distinct directory URLs to probe, from endpoint parents + common dirs."""
    base = urlsplit(target)
    origin_parts = (base.scheme, base.netloc, "", "", "")
    seen: list[str] = []

    def _add(scheme: str, netloc: str, path: str) -> None:
        url = urlunsplit((scheme, netloc, path, "", ""))
        if url not in seen:
            seen.append(url)

    for url in endpoint_urls:
        parts = urlsplit(url)
        if not parts.scheme or not parts.netloc:
            continue
        for dpath in _dir_paths(parts.path):
            _add(parts.scheme, parts.netloc, dpath)

    if base.scheme and base.netloc:
        for dpath in COMMON_DIRS:
            _add(origin_parts[0], origin_parts[1], dpath)

    return seen


@register
class DirectoryListingScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "directory-listing"
    min_aggressiveness = Aggressiveness.NORMAL

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        emitted: set[str] = set()
        probed = 0
        urls = candidate_dirs(ctx.config.target, [ep.url for ep in ctx.endpoints])

        for url in urls:
            if probed >= MAX_DIRS:
                break
            if not ctx.scope.is_allowed(url):
                continue
            probed += 1
            resp = await self._get(ctx, url)
            if resp is None or resp.status_code != 200:
                continue
            if not is_directory_listing(resp.text):
                continue
            path = urlsplit(url).path or "/"
            if path in emitted:
                continue
            emitted.add(path)
            yield self._finding(url, path)

    async def _get(self, ctx: ScanContext, url: str) -> httpx.Response | None:
        try:
            return await ctx.http.get(url, follow_redirects=False)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("directory-listing probe failed for %s: %s", url, exc)
            return None

    def _finding(self, url: str, path: str) -> Finding:
        return Finding(
            vuln_type="directory-listing",
            title=f"Directory listing enabled: {path}",
            severity=Severity.MEDIUM,
            confidence=Confidence.FIRM,
            url=url,
            description=(
                f"The directory {path} returns an auto-generated index of its contents "
                "instead of a 403 or an index page. Directory listings disclose file "
                "names, backups, source files, and the application's internal layout - "
                "valuable reconnaissance that can reveal otherwise-unlinked sensitive files."
            ),
            remediation=(
                "Disable automatic directory indexing (Apache: 'Options -Indexes'; Nginx: "
                "'autoindex off'; IIS: turn off Directory Browsing). Place an index file in "
                "each web-served directory and deny access to directories that should not be "
                "browsed."
            ),
            cwe="CWE-548",
            scanner=SCANNER_NAME,
            evidence=Evidence(matched_at="autoindex", notes="directory-listing marker in body"),
        )


__all__ = [
    "DirectoryListingScanner",
    "is_directory_listing",
    "candidate_dirs",
    "COMMON_DIRS",
]
