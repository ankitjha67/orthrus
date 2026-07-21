"""WebSocket workbench - scope-enforced connect / send / fuzz (Burp/Caido WS parity).

A Repeater and mini-Intruder for WebSockets: connect to an authorized ``ws://`` or
``wss://`` endpoint, send one or more messages (optionally with a chosen ``Origin``
and headers), and collect the frames the server sends back. Fuzz mode substitutes a
``§`` marker in a template with each payload and ranks the responses.

Scope enforcement is load-bearing: the endpoint host is validated against the
authorized scope before any connection is made. The ``websockets`` library is
optional; without it the tools report a clear error rather than crashing.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from orthrus.utils.scope import ScopeValidator

MARKER = "§"


@dataclass
class WsExchange:
    """One WebSocket session: what was sent, what came back, or why it failed."""

    url: str
    sent: list[str] = field(default_factory=list)
    received: list[str] = field(default_factory=list)
    elapsed_ms: float = 0.0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


async def _default_connect(url: str, headers: dict[str, str] | None, origin: str | None):
    import websockets
    extra = list((headers or {}).items())
    if origin:
        extra.append(("Origin", origin))
    return await websockets.connect(url, additional_headers=extra or None)


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


async def ws_exchange(
    url: str,
    messages: list[str],
    validator: ScopeValidator | None,
    *,
    origin: str | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 8.0,  # noqa: ASYNC109 - drives asyncio.wait_for on the connect
    recv_each: float = 1.0,
    connector: Callable[..., Awaitable[object]] | None = None,
) -> WsExchange:
    """Connect (scope-checked), send each message, and gather the frames received.

    After each send, frames are drained until the socket is quiet for ``recv_each``
    seconds. ``connector`` is injectable for tests; by default the ``websockets``
    library is used.
    """
    from time import perf_counter

    host = _host(url)
    if validator is not None and host and not validator.host_in_scope(host):
        return WsExchange(url=url, error=f"blocked: {host} out of scope")

    connect = connector or _default_connect
    start = perf_counter()
    try:
        conn = await asyncio.wait_for(connect(url, headers, origin), timeout=timeout)
    except (TimeoutError, OSError, ValueError) as exc:
        return WsExchange(url=url, error=f"{type(exc).__name__}: {exc}")
    except Exception as exc:  # noqa: BLE001 - websockets raises many bespoke errors
        return WsExchange(url=url, error=f"{type(exc).__name__}: {exc}")

    received: list[str] = []
    try:
        for msg in messages:
            await conn.send(msg)
            while True:
                try:
                    frame = await asyncio.wait_for(conn.recv(), timeout=recv_each)
                except TimeoutError:
                    break
                except Exception:  # noqa: BLE001 - closed / protocol errors end the read
                    break
                received.append(frame if isinstance(frame, str)
                                else bytes(frame).decode("utf-8", "replace"))
    finally:
        try:
            await conn.close()
        except Exception:  # noqa: BLE001
            pass
    return WsExchange(url=url, sent=list(messages), received=received,
                      elapsed_ms=round((perf_counter() - start) * 1000.0, 1))


def build_messages(template: str, payload: str) -> list[str]:
    """A single message: the template with its §marker§ replaced by the payload."""
    return [template.replace(MARKER, payload) if MARKER in template else payload]


async def ws_fuzz(
    url: str,
    template: str,
    payloads: list[str],
    validator: ScopeValidator | None,
    *,
    match: str | None = None,
    concurrency: int = 4,
    **kwargs,
) -> list[tuple[str, WsExchange, bool]]:
    """Send each payload (substituted into ``template``); return (payload, exchange, matched)."""
    sem = asyncio.Semaphore(max(1, concurrency))

    async def one(payload: str) -> tuple[str, WsExchange, bool]:
        async with sem:
            ex = await ws_exchange(url, build_messages(template, payload), validator, **kwargs)
            hit = bool(match) and any(match in f for f in ex.received)
            return payload, ex, hit

    return await asyncio.gather(*[one(p) for p in payloads])


__all__ = ["WsExchange", "ws_exchange", "ws_fuzz", "build_messages", "MARKER"]
