"""SCA scanner: known-vulnerable front-end JS library detection."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Severity
from orthrus.scanners.sca import SCAScanner, find_vulnerable_libs


# ------------------------------------------------------------- pure detector
def test_detects_outdated_jquery() -> None:
    hits = find_vulnerable_libs("/*! jQuery v1.7.1 */ var x=1;")
    assert len(hits) == 1
    assert hits[0]["name"] == "jQuery"
    assert hits[0]["version"] == "1.7.1"


def test_ignores_patched_version() -> None:
    assert find_vulnerable_libs("/*! jQuery v3.7.1 */") == []


def test_detects_prototype_pollution_libs() -> None:
    names = {h["name"] for h in find_vulnerable_libs("lodash 4.17.10 ... Handlebars v4.0.5")}
    assert {"lodash", "Handlebars"} <= names


def test_angularjs_is_eol_any_version() -> None:
    hits = find_vulnerable_libs("AngularJS v1.8.3")
    assert hits and hits[0]["name"] == "AngularJS"


def test_dedupes_per_library() -> None:
    # Two jQuery mentions -> a single finding.
    hits = find_vulnerable_libs("jQuery v1.7.1 ... jquery-1.7.1.min.js")
    assert len([h for h in hits if h["name"] == "jQuery"]) == 1


# ------------------------------------------------------------ scanner harness
class FakeResp:
    def __init__(self, text: str) -> None:
        self.text = text


class JsHttp:
    def __init__(self, body: str) -> None:
        self._body = body

    async def get(self, url: str, **kw: object) -> FakeResp:
        return FakeResp(self._body if url.endswith(".js") else "<html></html>")


def _ctx(endpoints: list[str], http: object) -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(target="http://h/"),
        endpoints=[SimpleNamespace(url=u) for u in endpoints],
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        http=http,
    )


async def test_scanner_flags_js_endpoint() -> None:
    ctx = _ctx(["http://h/app.js", "http://h/page"], JsHttp("/*! jQuery v1.7.1 */"))
    findings = [f async for f in SCAScanner().scan(ctx)]
    vc = [f for f in findings if f.vuln_type == "vulnerable-component"]
    assert len(vc) == 1
    assert vc[0].severity == Severity.MEDIUM
    assert "jQuery" in vc[0].title


async def test_scanner_ignores_non_js_and_clean_js() -> None:
    ctx = _ctx(["http://h/clean.js"], JsHttp("var ok = 1;"))
    findings = [f async for f in SCAScanner().scan(ctx)]
    assert [f for f in findings if f.vuln_type == "vulnerable-component"] == []
