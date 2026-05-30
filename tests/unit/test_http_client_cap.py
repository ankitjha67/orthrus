"""Hostile-response size cap: the client must never read an unbounded body.

A malicious target can return a multi-gigabyte (or endless chunked, or gzip-bomb)
response to exhaust the scanner's memory. ``HttpClient`` streams the body and
stops at ``max_response_bytes``, re-seating the truncated bytes so ``.text`` /
``.content`` / ``.json()`` still work downstream.
"""

from __future__ import annotations

import httpx

from orthrus.core.config import ScopeConfig
from orthrus.core.http_client import HttpClient
from orthrus.utils.rate_limiter import RateLimiter
from orthrus.utils.scope import ScopeValidator


def _client(handler, *, cap: int) -> HttpClient:
    scope = ScopeValidator(ScopeConfig(domains=["test.local"], ports=[80]))
    rl = RateLimiter(1000.0, burst=1000, adaptive=False)
    client = HttpClient(scope, rl, max_response_bytes=cap)
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client


async def test_oversized_streamed_body_is_truncated_to_cap():
    """A 1 MB body streamed in 10 KB chunks is cut off at a 50 KB cap."""

    def handler(request: httpx.Request) -> httpx.Response:
        async def gen():
            for _ in range(100):  # 100 * 10 KB = 1 MB, far over the cap
                yield b"A" * 10_000

        return httpx.Response(200, content=gen())

    client = _client(handler, cap=50_000)
    try:
        resp = await client.get("http://test.local/x", follow_redirects=False)
        assert len(resp.content) <= 50_000  # body bounded, not the full 1 MB
        assert resp.text.startswith("AAAA")  # still decodable after truncation
    finally:
        await client.aclose()


async def test_under_cap_body_is_fully_read():
    """A small body well under the cap is returned intact (no regression)."""
    payload = b'{"ok": true, "items": [1, 2, 3]}'

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=payload)

    client = _client(handler, cap=50_000)
    try:
        resp = await client.get("http://test.local/x", follow_redirects=False)
        assert resp.content == payload
        assert resp.json() == {"ok": True, "items": [1, 2, 3]}
    finally:
        await client.aclose()


async def test_empty_body_is_handled():
    """A bodyless response (e.g. 204/HEAD-like) reads cleanly under the cap."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(204)

    client = _client(handler, cap=50_000)
    try:
        resp = await client.get("http://test.local/x", follow_redirects=False)
        assert resp.status_code == 204
        assert resp.content == b""
    finally:
        await client.aclose()
