"""Request replayer (mini-Repeater): parse, tweak, and scope-enforced resend."""

from __future__ import annotations

import asyncio

import httpx

from orthrus.core.config import ScopeConfig
from orthrus.proxy import replay as R
from orthrus.utils.scope import ScopeValidator


def _validator(*domains: str) -> ScopeValidator:
    return ScopeValidator(ScopeConfig(domains=list(domains)))


def test_parse_origin_form_builds_url_from_host():
    spec = R.parse_raw_http("GET /a?b=1 HTTP/1.1\r\nHost: t.example\r\nX-K: v\r\n\r\n")
    assert spec.method == "GET" and spec.url == "https://t.example/a?b=1"
    assert spec.headers["Host"] == "t.example" and spec.headers["X-K"] == "v"


def test_parse_absolute_form_and_body():
    spec = R.parse_raw_http("POST http://t/x HTTP/1.1\nContent-Type: application/json\n\n{\"a\":1}")
    assert spec.method == "POST" and spec.url == "http://t/x"
    assert spec.body == '{"a":1}'


def test_tweaked_replaces_header_case_insensitively():
    base = R.RequestSpec(method="GET", url="http://t/x", headers={"Accept": "old"})
    out = base.tweaked(method="post", set_headers={"accept": "new"}, body="hi")
    assert out.method == "POST" and out.body == "hi"
    assert list(out.headers) == ["accept"] and out.headers["accept"] == "new"


def test_replay_blocks_out_of_scope():
    res = asyncio.run(R.replay(R.RequestSpec(url="http://evil.test/"), _validator("t")))
    assert not res.ok and res.error and "out of scope" in res.error


def test_replay_sends_in_scope(monkeypatch):
    class _Resp:
        status_code, reason_phrase, url = 200, "OK", "http://t/x"
        headers = httpx.Headers({"server": "test"})
        text = "pong"

    class _Client:
        def __init__(self, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, **kw):
            return _Resp()

    monkeypatch.setattr(R.httpx, "AsyncClient", _Client)
    res = asyncio.run(R.replay(R.RequestSpec(method="GET", url="http://t/x"), _validator("t")))
    assert res.ok and res.status == 200 and res.body == "pong"
    assert res.elapsed_ms >= 0.0
