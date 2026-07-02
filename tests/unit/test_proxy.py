"""Scope-aware capturing proxy (`orthrus proxy`).

Pure parse/serialize/extract helpers, plus loopback integration: a real proxy in
front of a tiny origin server, driven by httpx through the proxy — asserting the
response relays, in-scope traffic is captured, and out-of-scope is blocked.
"""

from __future__ import annotations

import asyncio

import httpx

from orthrus.core.config import ScopeConfig
from orthrus.core.schemas import HttpMethod, ParamLocation
from orthrus.proxy.server import (
    ProxyServer,
    build_response_head,
    extract_endpoint,
    parse_request_head,
)

# --- pure helpers --------------------------------------------------------

def test_parse_request_head():
    head = b"GET http://t/x?a=1 HTTP/1.1\r\nHost: t\r\nX-Foo: bar\r\nConnection: keep-alive"
    req = parse_request_head(head)
    assert req.method == "GET" and req.target == "http://t/x?a=1" and req.version == "HTTP/1.1"
    assert req.header("host") == "t" and req.header("x-foo") == "bar"
    # hop-by-hop + Host stripped from forwarded headers.
    fwd = req.forward_headers()
    assert "Connection" not in fwd and "Host" not in fwd and fwd["X-Foo"] == "bar"


def test_parse_request_head_rejects_malformed():
    try:
        parse_request_head(b"GARBAGE")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_build_response_head():
    raw = build_response_head(404, "Not Found", [("Content-Type", "text/plain"), ("Content-Length", "3")])
    assert raw.startswith(b"HTTP/1.1 404 Not Found\r\n")
    assert b"Content-Type: text/plain\r\n" in raw and raw.endswith(b"\r\n\r\n")


def test_extract_endpoint_query_and_body_params():
    ep = extract_endpoint(
        "POST", "http://t/login?ref=home",
        content_type="application/x-www-form-urlencoded", body=b"user=alice&pw=secret",
        response_status=200,
    )
    assert ep.method == HttpMethod.POST and ep.response_status == 200 and ep.source == "proxy"
    locs = {(p.name, p.location) for p in ep.params}
    assert ("ref", ParamLocation.QUERY) in locs
    assert ("user", ParamLocation.BODY) in locs and ("pw", ParamLocation.BODY) in locs


def test_extract_endpoint_unknown_method_falls_back():
    assert extract_endpoint("WEIRD", "http://t/").method == HttpMethod.GET


# --- loopback integration ------------------------------------------------

async def _origin(body: bytes = b"hello") -> tuple[asyncio.AbstractServer, int]:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.readuntil(b"\r\n\r\n")
        except asyncio.IncompleteReadError:
            pass
        head = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\n\r\n"
        writer.write(head.encode() + body)
        await writer.drain()
        writer.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1]


async def _run_through_proxy(scope: ScopeConfig, path: str, oport: int):
    captured: list = []
    server = ProxyServer(scope, on_capture=lambda ep: captured.append(ep))
    psrv = await server.serve("127.0.0.1", 0)
    pport = psrv.sockets[0].getsockname()[1]
    try:
        async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{pport}", timeout=5.0) as c:
            resp = await c.get(f"http://127.0.0.1:{oport}{path}")
        return resp, captured, server
    finally:
        psrv.close()
        await psrv.wait_closed()


async def test_proxy_forwards_and_captures_in_scope():
    origin, oport = await _origin(b"hello")
    try:
        scope = ScopeConfig(ip_ranges=["127.0.0.1/32"], ports=[])  # any port
        resp, captured, server = await _run_through_proxy(scope, "/hi?x=1", oport)
        assert resp.status_code == 200 and resp.text == "hello"
        assert len(captured) == 1 and server.captured == 1
        ep = captured[0]
        assert ep.url.endswith("/hi?x=1")
        assert ep.params[0].name == "x" and ep.params[0].value == "1"
    finally:
        origin.close()
        await origin.wait_closed()


async def test_proxy_blocks_out_of_scope():
    origin, oport = await _origin()
    try:
        scope = ScopeConfig(domains=["example.com"], ports=[])  # 127.0.0.1 not authorized
        resp, captured, server = await _run_through_proxy(scope, "/secret", oport)
        assert resp.status_code == 403
        assert captured == [] and server.blocked == 1
    finally:
        origin.close()
        await origin.wait_closed()


async def test_proxy_passthrough_does_not_capture():
    origin, oport = await _origin(b"ok")
    try:
        # out-of-scope host, but allow_out_of_scope → forwarded (relayed) yet not captured.
        captured: list = []
        server = ProxyServer(ScopeConfig(domains=["example.com"], ports=[]),
                             on_capture=lambda ep: captured.append(ep), allow_out_of_scope=True)
        psrv = await server.serve("127.0.0.1", 0)
        pport = psrv.sockets[0].getsockname()[1]
        try:
            async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{pport}", timeout=5.0) as c:
                resp = await c.get(f"http://127.0.0.1:{oport}/x")
            assert resp.status_code == 200 and resp.text == "ok"
            assert captured == []  # pass-through traffic is never captured
        finally:
            psrv.close()
            await psrv.wait_closed()
    finally:
        origin.close()
        await origin.wait_closed()
