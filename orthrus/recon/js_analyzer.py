"""JavaScript analysis (PRD §5.2 API endpoint extraction, §5.3 JS libs).

Parses JS for API endpoints, WebSocket URLs, and leaked secrets. The pure
extractors are reused by the crawler (for inline scripts); ``JsAnalyzer`` fetches
external script files discovered during crawling and feeds their findings back
into the asset inventory.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from urllib.parse import urljoin, urlsplit

import httpx

from orthrus.core import schemas
from orthrus.core.context import ScanContext
from orthrus.core.schemas import Endpoint, HttpMethod
from orthrus.recon.base import BaseRecon
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("recon.js")

MAX_FILES = 60

_ENDPOINT_PATTERNS = [
    re.compile(r"""\bfetch\(\s*['"]([^'"]+)['"]""", re.I),
    re.compile(r"""\baxios\.(?:get|post|put|delete|patch)\(\s*['"]([^'"]+)['"]""", re.I),
    re.compile(r"""\.open\(\s*['"][A-Z]+['"]\s*,\s*['"]([^'"]+)['"]""", re.I),
    re.compile(r"""['"]((?:https?:)?//[^'"\s]+)['"]"""),
    re.compile(r"""['"](/[A-Za-z0-9_][A-Za-z0-9_./\-]*)['"]"""),
    re.compile(r"""\burl\s*:\s*['"]([^'"]+)['"]""", re.I),
]

_WS_PATTERNS = [
    re.compile(r"""(wss?://[^'"\s]+)"""),
    re.compile(r"""new\s+WebSocket\(\s*['"]([^'"]+)['"]""", re.I),
]

_SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
    ("Generic secret assignment",
     re.compile(r"""(?i)\b(?:api[_-]?key|secret|token|passwd|password)\b['"]?\s*[:=]\s*['"]([A-Za-z0-9_\-]{12,})['"]""")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
]

# Endpoint matches to ignore (asset paths / noise).
_IGNORE_SUFFIX = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".woff2", ".ico", ".map")


def extract_endpoints(js: str, base_url: str) -> set[str]:
    found: set[str] = set()
    for pattern in _ENDPOINT_PATTERNS:
        for match in pattern.findall(js):
            value = match if isinstance(match, str) else match[0]
            value = value.strip()
            if not value or value.startswith(("data:", "mailto:", "javascript:", "#")):
                continue
            if value.lower().endswith(_IGNORE_SUFFIX):
                continue
            resolved = urljoin(base_url, value)
            if urlsplit(resolved).scheme in ("http", "https"):
                found.add(resolved.split("#", 1)[0])
    return found


def extract_websockets(js: str, base_url: str) -> set[str]:
    found: set[str] = set()
    for pattern in _WS_PATTERNS:
        for value in pattern.findall(js):
            value = value.strip()
            resolved = urljoin(base_url, value)
            scheme = urlsplit(resolved).scheme
            if scheme in ("ws", "wss"):
                found.add(resolved)
            elif scheme in ("http", "https"):  # new WebSocket("/ws") resolved to http
                found.add(("wss" if scheme == "https" else "ws") + resolved[len(scheme):])
    return found


def extract_secrets(js: str) -> list[tuple[str, str]]:
    secrets: list[tuple[str, str]] = []
    for label, pattern in _SECRET_PATTERNS:
        for match in pattern.findall(js):
            value = match if isinstance(match, str) else (match[0] if match else "")
            secrets.append((label, value or label))
    return secrets


class JsAnalyzer(BaseRecon):
    name = "js-analyzer"

    async def discover(self, ctx: ScanContext) -> AsyncIterator[schemas.Endpoint]:
        js_endpoints = [
            ep for ep in ctx.endpoints
            if ep.source == "script" or ep.url.split("?", 1)[0].lower().endswith(".js")
        ]
        seen_urls: set[str] = set()
        seen_ws: set[str] = set(ctx.websockets)
        emitted: set[str] = set()

        for ep in js_endpoints[:MAX_FILES]:
            if ep.url in seen_urls or not ctx.scope.is_allowed(ep.url):
                continue
            seen_urls.add(ep.url)
            try:
                resp = await ctx.http.get(ep.url)
            except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL):
                continue
            body = resp.text

            for url in extract_endpoints(body, ep.url):
                if url in emitted or not ctx.scope.is_allowed(url):
                    continue
                emitted.add(url)
                yield Endpoint(url=url, method=HttpMethod.GET, source="js")

            for ws in extract_websockets(body, ep.url):
                if ws not in seen_ws:
                    seen_ws.add(ws)
                    ctx.websockets.append(ws)

            for label, value in extract_secrets(body):
                logger.warning("possible secret in %s: %s (%s)", ep.url, label, value[:8] + "…")


__all__ = [
    "JsAnalyzer",
    "extract_endpoints",
    "extract_websockets",
    "extract_secrets",
]
