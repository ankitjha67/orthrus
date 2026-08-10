"""SCA scanner: known-vulnerable front-end JS library detection."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Severity
from orthrus.scanners.sca import (
    Component,
    SCAManifestScanner,
    SCAScanner,
    find_vulnerable_libs,
    match_components,
    parse_composer_lock,
    parse_gemfile_lock,
    parse_package_lock,
    parse_requirements,
    parse_yarn_lock,
)


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


# ================= server-side SCA: manifest parsers + matching =============
def test_parse_package_lock_v2_and_v1() -> None:
    v3 = (
        '{"lockfileVersion":3,"packages":{"":{"name":"app"},'
        '"node_modules/lodash":{"version":"4.17.20"},'
        '"node_modules/@scope/pkg":{"version":"1.0.0"}}}'
    )
    got = {(c.name, c.version) for c in parse_package_lock(v3)}
    assert ("lodash", "4.17.20") in got
    assert ("@scope/pkg", "1.0.0") in got

    v1 = '{"dependencies":{"lodash":{"version":"4.17.20","dependencies":{"nested":{"version":"1.2.3"}}}}}'
    got1 = {(c.name, c.version) for c in parse_package_lock(v1)}
    assert ("lodash", "4.17.20") in got1
    assert ("nested", "1.2.3") in got1  # nested deps walked

    assert parse_package_lock("not json{") == []


def test_parse_composer_lock_strips_v_prefix() -> None:
    text = (
        '{"packages":[{"name":"guzzlehttp/guzzle","version":"v7.4.0"}],'
        '"packages-dev":[{"name":"phpunit/phpunit","version":"9.5.0"}]}'
    )
    d = {c.name: c.version for c in parse_composer_lock(text)}
    assert d["guzzlehttp/guzzle"] == "7.4.0"  # leading v stripped
    assert d["phpunit/phpunit"] == "9.5.0"


def test_parse_requirements_only_exact_pins() -> None:
    text = "Django==3.2.10\nrequests>=2.0  # not pinned\nflask==2.0.1\n# comment line\n"
    d = {c.name: c.version for c in parse_requirements(text)}
    assert d == {"django": "3.2.10", "flask": "2.0.1"}


def test_parse_gemfile_lock_top_level_specs_only() -> None:
    text = (
        "GEM\n  remote: https://rubygems.org/\n  specs:\n"
        "    rack (2.2.3)\n    nokogiri (1.13.0)\n      racc (~> 1.4)\n\nPLATFORMS\n"
    )
    d = {c.name: c.version for c in parse_gemfile_lock(text)}
    assert d.get("rack") == "2.2.3"
    assert d.get("nokogiri") == "1.13.0"
    assert "racc" not in d  # 6-space transitive dep with a constraint, not an exact spec


def test_parse_yarn_lock_including_scoped() -> None:
    text = (
        'lodash@^4.17.0:\n  version "4.17.20"\n  resolved "x"\n\n'
        '"@babel/core@^7.0.0":\n  version "7.1.0"\n'
    )
    d = {c.name: c.version for c in parse_yarn_lock(text)}
    assert d.get("lodash") == "4.17.20"
    assert d.get("@babel/core") == "7.1.0"  # scoped name preserved


def test_match_components_against_rules() -> None:
    comps = [
        Component("npm", "lodash", "4.17.20"),  # < 4.17.21 -> hit
        Component("npm", "lodash", "4.17.21"),  # patched -> not a second hit
        Component("pypi", "django", "3.2.10"),  # < 3.2.14 -> hit
        Component("npm", "unknownpkg", "1.0.0"),  # no rule
        Component("npm", "lodash", "dev-master"),  # unparseable version -> skipped
    ]
    hits = {(h["ecosystem"], h["name"]) for h in match_components(comps)}
    assert ("npm", "lodash") in hits
    assert ("pypi", "django") in hits
    assert ("npm", "unknownpkg") not in hits


# ---------------------------------------------------- manifest scanner e2e
class FakeResp2:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text


class ManifestHttp:
    def __init__(self, routes: dict[str, str]) -> None:
        self.routes = routes

    async def get(self, url: str, **kw: object) -> FakeResp2:
        from urllib.parse import urlsplit

        path = urlsplit(url).path
        if path in self.routes:
            return FakeResp2(200, self.routes[path])
        return FakeResp2(404, "not found")


async def test_manifest_scanner_flags_exposure_and_vulnerable_component() -> None:
    composer = '{"packages":[{"name":"guzzlehttp/guzzle","version":"7.4.0"}]}'  # < 7.4.5
    ctx = _ctx([], ManifestHttp({"/composer.lock": composer}))
    findings = [f async for f in SCAManifestScanner().scan(ctx)]

    exposure = [f for f in findings if f.vuln_type == "info-disclosure"]
    vuln = [f for f in findings if f.vuln_type == "vulnerable-component"]
    assert len(exposure) == 1 and "composer.lock" in exposure[0].title
    assert len(vuln) == 1 and "guzzle" in vuln[0].title.lower()
    assert vuln[0].severity == Severity.MEDIUM


async def test_manifest_scanner_exposure_without_known_vuln() -> None:
    # A manifest with only patched deps still flags the *exposure* (info leak),
    # but no vulnerable-component finding.
    reqs = "flask==2.99.0\nrequests==99.0.0\n"
    ctx = _ctx([], ManifestHttp({"/requirements.txt": reqs}))
    findings = [f async for f in SCAManifestScanner().scan(ctx)]
    assert [f for f in findings if f.vuln_type == "info-disclosure"]
    assert [f for f in findings if f.vuln_type == "vulnerable-component"] == []
