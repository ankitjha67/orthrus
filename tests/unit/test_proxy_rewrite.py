"""Match & Replace engine for the proxy (add/modify/drop headers, rewrite bodies)."""

from __future__ import annotations

import json

from orthrus.proxy.rewrite import RewriteEngine, load_rules

RULES = json.dumps([
    {"part": "req-header", "match": "+", "replace": "X-Bug-Bounty: myhandle"},
    {"part": "req-header", "match": "(?i)^User-Agent:.*", "replace": "User-Agent: ORTHRUS"},
    {"part": "resp-header", "match": "(?i)^Content-Security-Policy:.*", "replace": ""},
    {"part": "req-body", "match": '"role":"user"', "replace": '"role":"admin"'},
    {"part": "resp-body", "match": "SECRET", "replace": "[redacted]"},
    {"part": "req-header", "match": "x", "replace": "y", "enabled": False},
    {"part": "bogus-part", "match": "a", "replace": "b"},
])


def test_load_rules_filters_unknown_and_disabled():
    rules = load_rules(RULES)
    assert len(rules) == 5                        # disabled + bogus-part dropped
    assert load_rules("") == [] and load_rules("[]") == []


def test_request_headers_add_and_modify():
    eng = RewriteEngine(load_rules(RULES))
    out = eng.request_headers([("Host", "t.test"), ("User-Agent", "curl/8")])
    d = dict(out)
    assert d["User-Agent"] == "ORTHRUS"           # modified
    assert d["X-Bug-Bounty"] == "myhandle"        # added
    assert d["Host"] == "t.test"                  # untouched


def test_response_header_drop_and_body_rewrites():
    eng = RewriteEngine(load_rules(RULES))
    resp = eng.response_headers([("Content-Type", "text/html"),
                                 ("Content-Security-Policy", "default-src 'self'")])
    names = {k for k, _ in resp}
    assert "Content-Type" in names and "Content-Security-Policy" not in names   # dropped

    assert eng.request_body(b'{"role":"user"}') == b'{"role":"admin"}'
    assert eng.response_body(b"the SECRET token") == b"the [redacted] token"


def test_no_rules_is_identity():
    eng = RewriteEngine([])
    assert eng.request_body(b"abc") == b"abc"
    assert eng.request_headers([("A", "b")]) == [("A", "b")]
    assert eng.request_headers_dict({"A": "b"}) == {"A": "b"}


def test_rewrite_applies_through_the_live_proxy(tmp_path):
    """End-to-end (plaintext): a resp-body rule rewrites what the client receives."""
    import asyncio

    import pytest
    pytest.importorskip("httpx")
    import httpx

    from orthrus.core.config import ScopeConfig
    from orthrus.proxy.server import ProxyServer

    async def origin(reader, writer):
        try:
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        except (TimeoutError, asyncio.IncompleteReadError):
            writer.close()
            return
        body = b"the SECRET token"
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
        await writer.drain()
        writer.close()

    async def run():
        srv = await asyncio.start_server(origin, "127.0.0.1", 0)
        origin_port = srv.sockets[0].getsockname()[1]
        eng = RewriteEngine(load_rules(RULES))   # includes resp-body SECRET -> [redacted]
        scope = ScopeConfig(domains=[], ip_ranges=["127.0.0.1/32"], ports=[origin_port])
        proxy = ProxyServer(scope, rewrite=eng, timeout=10)
        psrv = await proxy.serve("127.0.0.1", 0)
        pport = psrv.sockets[0].getsockname()[1]
        try:
            async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{pport}", timeout=10) as client:
                r = await client.get(f"http://127.0.0.1:{origin_port}/x")
        finally:
            psrv.close()
            srv.close()
            await psrv.wait_closed()
            await srv.wait_closed()
        assert r.status_code == 200
        assert r.text == "the [redacted] token"     # the resp-body rule fired

    asyncio.run(run())
