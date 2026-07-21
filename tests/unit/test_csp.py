"""Content-Security-Policy weakness analyzer tests.

Covers the pure parse/analyze detectors (positive + negative cases, including
that a MISSING CSP is silent so it never duplicates the headers scanner) plus
the scanner end-to-end against duck-typed fakes.
"""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Severity
from orthrus.scanners.csp_analyzer import (
    CspAnalyzerScanner,
    analyze_csp,
    parse_csp,
)


# ------------------------------------------------------------- pure detectors
def test_parse_csp_splits_directives_lowercased() -> None:
    out = parse_csp("default-src 'self'; Script-Src 'self' https://CDN.example.com")
    assert out["default-src"] == ["'self'"]
    assert out["script-src"] == ["'self'", "https://cdn.example.com"]


def test_analyze_csp_missing_policy_is_silent() -> None:
    # The headers scanner owns "missing CSP" - this analyzer must stay quiet.
    assert analyze_csp(None) == []
    assert analyze_csp("") == []
    assert analyze_csp("   ") == []


def test_analyze_csp_flags_unsafe_inline_and_eval() -> None:
    weaknesses = analyze_csp(
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "object-src 'none'; frame-ancestors 'none'"
    )
    titles = {t for _s, t, _d in weaknesses}
    assert "CSP allows 'unsafe-inline' scripts" in titles
    assert "CSP allows 'unsafe-eval' scripts" in titles
    assert all(sev == Severity.MEDIUM for sev, t, _d in weaknesses if "unsafe" in t)


def test_analyze_csp_flags_wildcard_and_data_scripts() -> None:
    weaknesses = analyze_csp("script-src * data:; object-src 'none'; frame-ancestors 'none'")
    titles = {t for _s, t, _d in weaknesses}
    assert "CSP script source allows any origin (*)" in titles
    assert "CSP allows data: scripts" in titles


def test_analyze_csp_inline_falls_back_to_default_src() -> None:
    # No script-src, so script restrictions come from default-src.
    weaknesses = analyze_csp(
        "default-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'"
    )
    titles = {t for _s, t, _d in weaknesses}
    assert "CSP allows 'unsafe-inline' scripts" in titles


def test_analyze_csp_missing_object_src_and_frame_ancestors() -> None:
    weaknesses = analyze_csp("default-src 'self'")
    titles = {t for _s, t, _d in weaknesses}
    assert "CSP missing object-src 'none'" in titles
    assert "CSP missing frame-ancestors (clickjacking)" in titles
    # default-src 'none' suppresses the object-src finding.
    strict = analyze_csp("default-src 'none'; frame-ancestors 'none'")
    assert all("object-src" not in t for _s, t, _d in strict)


def test_analyze_csp_flags_http_sources() -> None:
    weaknesses = analyze_csp(
        "default-src 'self'; img-src http://images.example.com; "
        "object-src 'none'; frame-ancestors 'none'"
    )
    titles = [t for _s, t, _d in weaknesses]
    assert "CSP permits insecure http: sources" in titles
    # Only flagged once even across multiple http: sources.
    assert titles.count("CSP permits insecure http: sources") == 1


def test_analyze_csp_strict_policy_is_clean() -> None:
    strict = (
        "default-src 'none'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"
    )
    assert analyze_csp(strict) == []


# ------------------------------------------------------------ scanner harness
class FakeResp:
    def __init__(self, status_code: int, text: str, headers: dict[str, str]) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = headers
        self.content_type = headers.get("Content-Type")


class FakeHttp:
    def __init__(self, csp: str | None) -> None:
        self._csp = csp

    async def get(self, url: str, **kw: object) -> FakeResp:
        headers = {"Content-Type": "text/html"}
        if self._csp is not None:
            headers["Content-Security-Policy"] = self._csp
        return FakeResp(200, "<html></html>", headers)


def _ctx(http: object) -> SimpleNamespace:
    return SimpleNamespace(
        endpoints=[],
        http=http,
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(target="http://h/"),
    )


async def test_scanner_flags_weak_csp_from_root_fetch() -> None:
    http = FakeHttp("script-src 'self' 'unsafe-inline'")
    findings = [f async for f in CspAnalyzerScanner().scan(_ctx(http))]
    assert findings, "expected weak-CSP findings"
    assert all(f.vuln_type == "csp" for f in findings)
    assert all(f.cwe == "CWE-693" for f in findings)
    titles = {f.title for f in findings}
    assert "CSP allows 'unsafe-inline' scripts" in titles
    inline = next(f for f in findings if "unsafe-inline" in f.title)
    assert inline.severity == Severity.MEDIUM
    assert "script-src" in (inline.evidence.matched_at or "")


async def test_scanner_silent_on_strict_csp() -> None:
    http = FakeHttp(
        "default-src 'none'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"
    )
    findings = [f async for f in CspAnalyzerScanner().scan(_ctx(http))]
    assert findings == []


async def test_scanner_silent_when_no_csp_present() -> None:
    # No CSP header at all -> the headers scanner handles "missing"; we stay quiet.
    http = FakeHttp(None)
    findings = [f async for f in CspAnalyzerScanner().scan(_ctx(http))]
    assert findings == []
