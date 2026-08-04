"""JavaScript analysis (PRD §5.2 API endpoint extraction, §5.3 JS libs).

Parses JS for API endpoints, WebSocket URLs, and leaked secrets. The pure
extractors are reused by the crawler (for inline scripts); ``JsAnalyzer`` fetches
external script files discovered during crawling and feeds their findings back
into the asset inventory.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from urllib.parse import parse_qsl, urljoin, urlsplit

import httpx

from orthrus.core import schemas
from orthrus.core.context import ScanContext
from orthrus.core.schemas import Endpoint, HttpMethod, Param, ParamLocation
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
    # Root-relative path, optionally carrying a ?query string. The trailing
    # ``(?:\?[^'"\s]*)?`` is what lets a JS-embedded filter link such as
    # ``"/catalog?category=Gin"`` survive with its query intact - without it the
    # char class stops at ``?`` and the injectable param is silently dropped.
    re.compile(r"""['"](/[A-Za-z0-9_][A-Za-z0-9_./\-]*(?:\?[^'"\s]*)?)['"]"""),
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


def params_from_query(url: str) -> list[Param]:
    """Parse a URL's query string into QUERY-location injection parameters.

    Shared by the crawler and JS analyzer so that a discovered ``?a=b`` link
    (from an anchor, an inline script, or an external JS file) is surfaced as an
    endpoint that actually carries its injectable parameters - otherwise a
    scanner has no injection point to test.
    """
    return [
        Param(name=name, location=ParamLocation.QUERY, value=value)
        for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True)
    ]


def extract_endpoints(js: str, base_url: str) -> set[str]:
    found: set[str] = set()
    for pattern in _ENDPOINT_PATTERNS:
        for match in pattern.findall(js):
            value = match if isinstance(match, str) else match[0]
            value = value.strip()
            if not value or value.startswith(("data:", "mailto:", "javascript:", "#")):
                continue
            # Test the suffix against the path only - a query string such as
            # ``/app.js?v=2`` must not defeat the static-asset filter, and a
            # legit endpoint like ``/catalog?x=1.css`` must not be dropped.
            path_only = value.split("?", 1)[0].split("#", 1)[0]
            if path_only.lower().endswith(_IGNORE_SUFFIX):
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
                yield Endpoint(
                    url=url,
                    method=HttpMethod.GET,
                    params=params_from_query(url),
                    source="js",
                )

            for ws in extract_websockets(body, ep.url):
                if ws not in seen_ws:
                    seen_ws.add(ws)
                    ctx.websockets.append(ws)

            for label, value in extract_secrets(body):
                # Redact to a non-recoverable preview (first 4 chars + ***),
                # matching the secret_scanner doctrine - never log a usable secret.
                logger.warning(
                    "possible secret in %s: %s (%s)", ep.url, label, value[:4] + "***"
                )


__all__ = [
    "JsAnalyzer",
    "extract_endpoints",
    "extract_websockets",
    "extract_secrets",
    "params_from_query",
]
