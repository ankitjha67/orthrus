"""Source-map recovery recon: locate + parse .map, mine original-source endpoints."""

from __future__ import annotations

import json
from types import SimpleNamespace

from orthrus.core.schemas import Endpoint, HttpMethod
from orthrus.recon.sourcemap_recovery import (
    SourceMapRecovery,
    endpoints_from_sourcemap,
    parse_sourcemap,
    sourcemap_url,
)


# ----------------------------------------------------------------- sourcemap_url
def test_sourcemap_url_from_comment_relative():
    body = "console.log(1)\n//# sourceMappingURL=app.min.js.map\n"
    assert sourcemap_url(body, "https://h/static/app.min.js") == "https://h/static/app.min.js.map"


def test_sourcemap_url_legacy_at_syntax():
    assert sourcemap_url("//@ sourceMappingURL=b.map", "https://h/a.js") == "https://h/b.map"


def test_sourcemap_url_ignores_inline_data_uri():
    assert sourcemap_url("//# sourceMappingURL=data:application/json;base64,xx", "https://h/a.js") is None


def test_sourcemap_url_none_when_absent():
    assert sourcemap_url("just code; no map", "https://h/a.js") is None


# ----------------------------------------------------------------- parse_sourcemap
def test_parse_sourcemap_extracts_sources_and_content():
    doc = {"version": 3, "sources": ["src/api.js"], "sourcesContent": ["const x=1"]}
    sources, content = parse_sourcemap(json.dumps(doc))
    assert sources == ["src/api.js"]
    assert content == ["const x=1"]


def test_parse_sourcemap_bad_json():
    assert parse_sourcemap("not json") == ([], [])


# ----------------------------------------------------------------- endpoint mining
def test_endpoints_from_sourcemap_mines_original_source():
    original = 'fetch("/api/internal/users"); axios.post("/api/admin/reset")'
    doc = {"version": 3, "sources": ["app.js"], "sourcesContent": [original]}
    found = endpoints_from_sourcemap(json.dumps(doc), "https://h/static/app.js")
    assert any("/api/internal/users" in u for u in found)
    assert any("/api/admin/reset" in u for u in found)


# ----------------------------------------------------------------- full discover flow
class _FakeResp:
    def __init__(self, text: str, status: int = 200) -> None:
        self.text = text
        self.status_code = status


class _FakeHttp:
    def __init__(self, routes: dict[str, _FakeResp]) -> None:
        self._routes = routes

    async def get(self, url: str, **kw: object) -> _FakeResp:
        return self._routes.get(url, _FakeResp("not found", 404))


def _ctx(routes: dict[str, _FakeResp], endpoints: list[Endpoint]) -> SimpleNamespace:
    return SimpleNamespace(
        endpoints=endpoints,
        websockets=[],
        http=_FakeHttp(routes),
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(target="https://h/"),
    )


async def test_discover_recovers_endpoints_from_map():
    js_url = "https://h/static/app.min.js"
    map_url = "https://h/static/app.min.js.map"
    js_body = "var a=1\n//# sourceMappingURL=app.min.js.map"
    map_doc = json.dumps({
        "version": 3,
        "sources": ["webpack://app/src/services/api.js"],
        "sourcesContent": ['export const get = () => fetch("/api/v2/secret-endpoint")'],
    })
    routes = {js_url: _FakeResp(js_body), map_url: _FakeResp(map_doc)}
    ctx = _ctx(routes, [Endpoint(url=js_url, method=HttpMethod.GET, source="script")])

    found = [ep async for ep in SourceMapRecovery().discover(ctx)]
    urls = {ep.url for ep in found}
    assert any("/api/v2/secret-endpoint" in u for u in urls)
    assert all(ep.source == "sourcemap" for ep in found)


async def test_discover_noop_without_map():
    js_url = "https://h/static/plain.js"
    ctx = _ctx(
        {js_url: _FakeResp("var a=1; // no source map here")},
        [Endpoint(url=js_url, method=HttpMethod.GET, source="script")],
    )
    # The .map fallback 404s, so nothing is recovered.
    assert [ep async for ep in SourceMapRecovery().discover(ctx)] == []
