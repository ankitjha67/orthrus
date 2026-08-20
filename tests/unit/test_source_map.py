"""JavaScript source-map exposure scanner + confirmer."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import httpx

from orthrus.core.schemas import (
    Confidence,
    Endpoint,
    Evidence,
    Finding,
    HttpMethod,
    Severity,
)
from orthrus.exploits.source_map_confirm import SourceMapConfirm
from orthrus.scanners.source_map import SourceMapScanner, parse_source_map

_MAP_WITH_CONTENT = json.dumps({
    "version": 3,
    "sources": ["webpack://app/src/index.js", "webpack://app/src/api.js"],
    "sourcesContent": ["const API_KEY='sk-internal';", "export function pay(){}"],
})
_MAP_PATHS_ONLY = json.dumps({
    "version": 3,
    "sources": ["src/index.js", "src/api.js"],
    "sourcesContent": [None, None],
})


# ----------------------------------------------------------------- detector
def test_parse_source_map() -> None:
    full = parse_source_map(_MAP_WITH_CONTENT)
    assert full is not None and full["has_content"] is True and len(full["sources"]) == 2

    paths = parse_source_map(_MAP_PATHS_ONLY)
    assert paths is not None and paths["has_content"] is False

    assert parse_source_map("not json{") is None
    assert parse_source_map('{"foo":1}') is None  # no version/sources
    assert parse_source_map('{"version":3,"sources":[]}') is None  # nothing to leak


# ------------------------------------------------------------------- scanner
class MapHttp:
    def __init__(self, body: str | None) -> None:
        self.body = body

    async def get(self, url: str, **kw: object) -> httpx.Response:
        if url.endswith(".map") and self.body is not None:
            return httpx.Response(200, text=self.body, request=httpx.Request("GET", url))
        return httpx.Response(404, text="not found", request=httpx.Request("GET", url))


def _ctx(http: object) -> SimpleNamespace:
    ep = Endpoint(url="http://h/static/app.js", method=HttpMethod.GET)
    return SimpleNamespace(
        endpoints=[ep],
        http=http,
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(target="http://h/"),
    )


def _scan(ctx: SimpleNamespace) -> list[Finding]:
    async def run():
        return [f async for f in SourceMapScanner().scan(ctx)]

    return asyncio.run(run())


def test_scanner_flags_full_source_high() -> None:
    findings = _scan(_ctx(MapHttp(_MAP_WITH_CONTENT)))
    sm = [f for f in findings if f.vuln_type == "source-map-exposure"]
    assert len(sm) == 1
    assert sm[0].severity == Severity.HIGH
    assert sm[0].cwe == "CWE-540"


def test_scanner_paths_only_is_medium() -> None:
    findings = _scan(_ctx(MapHttp(_MAP_PATHS_ONLY)))
    sm = [f for f in findings if f.vuln_type == "source-map-exposure"]
    assert len(sm) == 1
    assert sm[0].severity == Severity.MEDIUM


def test_scanner_quiet_without_map() -> None:
    assert _scan(_ctx(MapHttp(None))) == []


# ----------------------------------------------------------------- confirmer
def _finding() -> Finding:
    return Finding(
        vuln_type="source-map-exposure",
        title="Exposed source map",
        severity=Severity.HIGH,
        confidence=Confidence.FIRM,
        url="http://h/static/app.js.map",
        cwe="CWE-540",
        scanner="source-map-exposure",
        evidence=Evidence(),
    )


class ConfirmMapHttp:
    def __init__(self, body: str) -> None:
        self.body = body

    async def get(self, url: str, **kw: object) -> httpx.Response:
        return httpx.Response(200, text=self.body, request=httpx.Request("GET", url))


def test_confirmer_extracts_reconstruction_sample() -> None:
    ctx = SimpleNamespace(http=ConfirmMapHttp(_MAP_WITH_CONTENT))
    result = asyncio.run(SourceMapConfirm().confirm(ctx, _finding()))
    assert result.success is True
    assert "recovered source snippet" in (result.extracted_data or "")
    assert "sk-internal" in (result.extracted_data or "")
