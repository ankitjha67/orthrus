"""WebSocket workbench - connect/send/receive, fuzz, and scope enforcement."""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("websockets")
import websockets  # noqa: E402

from orthrus.core.config import ScopeConfig  # noqa: E402
from orthrus.proxy.ws import build_messages, ws_exchange, ws_fuzz  # noqa: E402
from orthrus.utils.scope import ScopeValidator  # noqa: E402


async def _echo(ws):
    async for msg in ws:
        # respond, and flag a "sql error" when the payload smells like injection
        reply = "sql error near ''" if "'" in msg else f"echo: {msg}"
        await ws.send(reply)


def _validator(*ip_ranges: str) -> ScopeValidator:
    return ScopeValidator(ScopeConfig(domains=[], ip_ranges=list(ip_ranges) or ["127.0.0.1/32"]))


def test_build_messages_substitutes_marker():
    assert build_messages("id=§", "42") == ["id=42"]
    assert build_messages("no marker", "42") == ["42"]      # no § -> the payload IS the message


def test_ws_exchange_sends_and_receives(tmp_path):
    async def run():
        server = await websockets.serve(_echo, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            ex = await ws_exchange(f"ws://127.0.0.1:{port}/socket", ["hello"],
                                   _validator(), recv_each=0.5, timeout=5)
        finally:
            server.close()
            await server.wait_closed()
        assert ex.ok and ex.sent == ["hello"]
        assert ex.received == ["echo: hello"]

    asyncio.run(run())


def test_ws_fuzz_flags_the_matching_payload(tmp_path):
    async def run():
        server = await websockets.serve(_echo, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            results = await ws_fuzz(f"ws://127.0.0.1:{port}/s", "id=§", ["1", "2'", "3"],
                                    _validator(), match="error", recv_each=0.5, timeout=5)
        finally:
            server.close()
            await server.wait_closed()
        by_payload = {p: (ex, hit) for p, ex, hit in results}
        assert by_payload["2'"][1] is True                          # the quote triggered "sql error"
        assert by_payload["1"][1] is False and by_payload["3"][1] is False
        assert "sql error near ''" in by_payload["2'"][0].received[0]

    asyncio.run(run())


def test_ws_scope_block_refuses_before_connecting():
    async def run():
        # allowed scope is 10.0.0.0/8; the target is loopback -> blocked, never dialed
        ex = await ws_exchange("ws://127.0.0.1:1/socket", ["x"], _validator("10.0.0.0/8"))
        assert not ex.ok and "out of scope" in ex.error

    asyncio.run(run())
