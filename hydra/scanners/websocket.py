"""WebSocket security scanner (PRD §6.8 WebSocket).

Tests WebSocket endpoints discovered by the JS analyzer for missing Origin
validation: if the server completes the handshake when sent an attacker Origin,
the endpoint is exposed to Cross-Site WebSocket Hijacking (CSWSH) when it relies
on cookie auth. Uses the websockets client; the host is scope-validated first.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from hydra.core.context import ScanContext
from hydra.core.schemas import Confidence, Evidence, Finding, Severity
from hydra.scanners.base_scanner import BaseScanner
from hydra.scanners.registry import register
from hydra.utils.logger import get_logger

logger = get_logger("scanner.websocket")

SCANNER_NAME = "websocket"
MAX_ENDPOINTS = 20
ATTACKER_ORIGIN = "https://hydra-attacker.example"

try:
    import websockets
except ImportError:
    websockets = None  # type: ignore[assignment]


def classify_ws(foreign_origin_accepted: bool) -> Severity | None:
    return Severity.MEDIUM if foreign_origin_accepted else None


async def _accepts_origin(uri: str, origin: str) -> bool:
    if websockets is None:
        return False
    try:
        conn = await asyncio.wait_for(
            websockets.connect(uri, additional_headers=[("Origin", origin)]), timeout=5.0
        )
        await conn.close()
        return True
    except Exception:
        return False


@register
class WebSocketScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "websocket"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        if websockets is None:
            logger.debug("websocket: websockets lib not installed; skipping")
            return
        seen: set[str] = set()
        for uri in ctx.websockets[:MAX_ENDPOINTS]:
            if uri in seen:
                continue
            seen.add(uri)
            host = urlsplit(uri).hostname
            if not host or not ctx.scope.host_in_scope(host):
                continue
            accepted = await _accepts_origin(uri, ATTACKER_ORIGIN)
            if classify_ws(accepted) is None:
                continue
            yield Finding(
                vuln_type="websocket",
                title="WebSocket accepts cross-origin connections (missing Origin validation)",
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                url=uri,
                description=(
                    f"The WebSocket endpoint completed the handshake with a foreign Origin "
                    f"({ATTACKER_ORIGIN}). If it authenticates via cookies, this enables "
                    "Cross-Site WebSocket Hijacking (an attacker page can open an authenticated "
                    "socket)."
                ),
                remediation=(
                    "Validate the Origin header on the WebSocket handshake against an allow-list, "
                    "and use per-connection CSRF-style tokens instead of relying on cookies."
                ),
                cwe="CWE-1385",
                scanner=SCANNER_NAME,
                evidence=Evidence(request_raw=f"Origin: {ATTACKER_ORIGIN}", matched_at=uri),
            )


__all__ = ["WebSocketScanner", "classify_ws"]
