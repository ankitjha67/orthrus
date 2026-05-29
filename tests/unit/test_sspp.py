"""Server-side prototype pollution scanner."""

from __future__ import annotations

import json
from types import SimpleNamespace

from orthrus.core.schemas import Severity
from orthrus.scanners.sspp import ServerSidePrototypePollutionScanner, pollution_confirmed


def test_pollution_confirmed() -> None:
    assert pollution_confirmed('{"id":1}', '{"id":1,"orthrusPPx":"polluted"}', "orthrusPPx") is True
    assert pollution_confirmed('{"orthrusPPx":1}', '{"orthrusPPx":1}', "orthrusPPx") is False  # echoed before
    assert pollution_confirmed('{"id":1}', '{"id":1}', "orthrusPPx") is False  # never appeared


class FakeResp:
    def __init__(self, text: str) -> None:
        self.text = text


def _ctx(http: object, urls: list[str]) -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(target="http://h/"),
        endpoints=[SimpleNamespace(url=u, params=[]) for u in urls],
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        http=http,
    )


class PollutableHttp:
    """Stateful: keys merged via __proto__ persist onto every later object."""

    def __init__(self) -> None:
        self.polluted: dict = {}

    async def request(self, method: str, url: str, **kw: object) -> FakeResp:
        body = kw.get("json") or {}
        proto = body.get("__proto__") if isinstance(body, dict) else None
        if isinstance(proto, dict):
            self.polluted.update(proto)
        return FakeResp(json.dumps({"id": 1, **self.polluted}))


class CleanHttp:
    async def request(self, method: str, url: str, **kw: object) -> FakeResp:
        return FakeResp('{"id":1,"role":"user"}')


async def test_scanner_confirms_sspp() -> None:
    ctx = _ctx(PollutableHttp(), ["http://h/api/merge"])
    findings = [f async for f in ServerSidePrototypePollutionScanner().scan(ctx)]
    pp = [f for f in findings if f.vuln_type == "prototype-pollution"]
    assert len(pp) == 1
    assert pp[0].severity == Severity.HIGH
    assert pp[0].cwe == "CWE-1321"


async def test_scanner_quiet_on_clean_endpoint() -> None:
    ctx = _ctx(CleanHttp(), ["http://h/api/merge"])
    findings = [f async for f in ServerSidePrototypePollutionScanner().scan(ctx)]
    assert [f for f in findings if f.vuln_type == "prototype-pollution"] == []


async def test_scanner_skips_non_api_endpoints() -> None:
    ctx = _ctx(PollutableHttp(), ["http://h/page"])
    findings = [f async for f in ServerSidePrototypePollutionScanner().scan(ctx)]
    assert findings == []
