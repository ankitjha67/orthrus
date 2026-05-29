"""Content discovery (PRD §5.5).

Scope-enforced directory/file brute-force with a built-in wordlist, soft-404
calibration, and sensitive-file detection (.env, .git, backups, admin panels).
Widens the attack surface for every downstream scanner. Confirmed-exposed
sensitive files are marked ``source="sensitive"`` for the exposed-files scanner.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from orthrus.core import schemas
from orthrus.core.context import ScanContext
from orthrus.core.schemas import Endpoint, HttpMethod
from orthrus.recon.base import BaseRecon
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("recon.content")

WORDLIST = [
    "admin", "administrator", "login", "dashboard", "config", "config.php",
    "config.json", "backup", "backup.zip", "backup.sql", "db.sql", "database.sql",
    "robots.txt", "sitemap.xml", ".env", ".env.local", ".env.production",
    ".git/HEAD", ".git/config", ".svn/entries", ".DS_Store", ".htaccess",
    "web.config", "phpinfo.php", "info.php", "server-status", "server-info",
    "api", "api/v1", "swagger.json", "openapi.json", ".well-known/security.txt",
    "wp-login.php", "wp-config.php.bak", "test", "debug", "console", "status",
    "health", "metrics", "actuator", "actuator/env",
]

SENSITIVE = {
    ".env", ".env.local", ".env.production", ".git/HEAD", ".git/config",
    ".svn/entries", ".DS_Store", "web.config", "wp-config.php.bak",
    "backup.zip", "backup.sql", "db.sql", "database.sql", "config.json",
}

_FOUND_STATUSES = {200, 204, 301, 302, 307, 401, 403}


def is_interesting(status: int, length: int, base_status: int | None, base_len: int | None) -> bool:
    if status not in _FOUND_STATUSES:
        return False
    if base_status is not None and status == base_status and base_len is not None:
        if abs(length - base_len) <= max(32, base_len * 0.05):
            return False  # matches the soft-404 baseline
    return True


def is_sensitive(path: str) -> bool:
    return path in SENSITIVE


def _looks_sensitive(path: str, text: str) -> bool:
    if path == ".git/HEAD":
        return "ref:" in text
    if path == ".git/config":
        return "[core]" in text or "repositoryformatversion" in text
    if path.startswith(".env"):
        return "=" in text and "<html" not in text.lower()
    return True  # other sensitive paths: trust the 200 + interesting check


class ContentDiscovery(BaseRecon):
    name = "content-discovery"

    async def discover(self, ctx: ScanContext) -> AsyncIterator[schemas.Endpoint]:
        parts = urlsplit(ctx.config.target if "://" in ctx.config.target else f"//{ctx.config.target}")
        root = f"{parts.scheme or 'http'}://{parts.netloc or parts.path}"

        # Prefer the orchestrator's shared catch-all profile (multiple probes,
        # structural fingerprint). Fall back to a local single-shot baseline
        # when running standalone (e.g. recon-only without an orchestrator).
        profile = ctx.baseline if ctx.baseline and ctx.baseline.fingerprints else None
        if profile is None:
            base_status, base_len = await self._baseline(ctx, root)
        else:
            base_status, base_len = None, None

        for path in WORDLIST:
            url = f"{root}/{path}"
            if not ctx.scope.is_allowed(url):
                continue
            try:
                resp = await ctx.http.get(url, follow_redirects=False)
            except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL):
                continue
            length = len(resp.content)
            if resp.status_code not in _FOUND_STATUSES:
                continue
            if profile is not None:
                if profile.matches(resp.status_code, resp.text):
                    continue  # looks like the calibrated catch-all, not a real hit
            elif not is_interesting(resp.status_code, length, base_status, base_len):
                continue

            sensitive = (
                is_sensitive(path)
                and resp.status_code == 200
                and _looks_sensitive(path, resp.text)
            )
            if sensitive:
                logger.warning("exposed sensitive file: %s (HTTP %s)", url, resp.status_code)
            yield Endpoint(
                url=url,
                method=HttpMethod.GET,
                response_status=resp.status_code,
                content_type=resp.headers.get("content-type"),
                content_length=length,
                source="sensitive" if sensitive else "content-discovery",
            )

    async def _baseline(self, ctx: ScanContext, root: str) -> tuple[int | None, int | None]:
        url = f"{root}/orthrus-not-found-{secrets.token_hex(6)}"
        if not ctx.scope.is_allowed(url):
            return None, None
        try:
            resp = await ctx.http.get(url, follow_redirects=False)
            return resp.status_code, len(resp.content)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL):
            return None, None


__all__ = ["ContentDiscovery", "is_interesting", "is_sensitive", "WORDLIST", "SENSITIVE"]
