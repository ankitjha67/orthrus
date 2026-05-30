"""API/HTTP misconfiguration scanner tests (XST + dangerous methods).

Covers the pure detectors (TRACE echo gating, dangerous-method parsing, origin
dedup) and the scanner end-to-end against duck-typed fakes.
"""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Severity
from orthrus.scanners.api_misconfig import (
    ApiMisconfigScanner,
    dangerous_methods,
    origins_from,
    trace_enabled,
)

_NONCE = "Orthrus-Xst-9c4f2a"


# ------------------------------------------------------------- pure detectors
def test_trace_enabled_requires_200_and_echoed_nonce() -> None:
    assert trace_enabled(200, f"TRACE / HTTP/1.1\nX-Orthrus-Xst: {_NONCE}\n", _NONCE) is True
    assert trace_enabled(405, f"...{_NONCE}...", _NONCE) is False  # method not allowed
    assert trace_enabled(200, "no echo here", _NONCE) is False  # nonce absent
    assert trace_enabled(200, "", _NONCE) is False


def test_dangerous_methods_extracts_risky_verbs() -> None:
    assert dangerous_methods("GET, HEAD, POST, PUT, DELETE, OPTIONS") == ["PUT", "DELETE"]
    assert dangerous_methods("get, head, options") == []  # only safe verbs
    assert dangerous_methods("OPTIONS, TRACE, PATCH, CONNECT") == ["PATCH", "TRACE", "CONNECT"]
    assert dangerous_methods("") == []


def test_dangerous_methods_is_case_and_whitespace_insensitive() -> None:
    assert dangerous_methods("  put ,  delete ") == ["PUT", "DELETE"]


def test_origins_from_dedupes_by_scheme_host() -> None:
    out = origins_from("http://h/a", ["http://h/b", "https://h2/c", "http://h/d"])
    assert out == ["http://h", "https://h2"]


# ------------------------------------------------------------ scanner harness
class FakeResp:
    def __init__(self, status_code: int, text: str = "", headers: dict[str, str] | None = None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.content_type = self.headers.get("content-type")


def _ctx(http: object) -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(target="http://h/"),
        endpoints=[],
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        http=http,
    )


class XstHttp:
    """TRACE echoes the request; OPTIONS advertises only safe methods."""

    async def request(self, method: str, url: str, **kw: object) -> FakeResp:
        if method == "TRACE":
            return FakeResp(200, f"TRACE / HTTP/1.1\r\nX-Orthrus-Xst: {_NONCE}\r\n")
        return FakeResp(200, headers={"Allow": "GET, HEAD, OPTIONS"})


class DangerousMethodsHttp:
    """TRACE is rejected; OPTIONS advertises PUT/DELETE."""

    async def request(self, method: str, url: str, **kw: object) -> FakeResp:
        if method == "TRACE":
            return FakeResp(405, "Method Not Allowed")
        return FakeResp(204, headers={"Allow": "GET, POST, PUT, DELETE, OPTIONS"})


class CleanHttp:
    async def request(self, method: str, url: str, **kw: object) -> FakeResp:
        if method == "TRACE":
            return FakeResp(405, "nope")
        return FakeResp(200, headers={"Allow": "GET, HEAD, OPTIONS"})


async def test_scanner_flags_xst() -> None:
    findings = [f async for f in ApiMisconfigScanner().scan(_ctx(XstHttp()))]
    xst = [f for f in findings if "Cross-Site Tracing" in f.title]
    assert len(xst) == 1
    assert xst[0].vuln_type == "api-misconfig"
    assert xst[0].severity == Severity.MEDIUM
    assert xst[0].cwe == "CWE-693"
    # the nonce must not leak in full into evidence request_raw
    assert _NONCE not in (xst[0].evidence.request_raw or "")


async def test_scanner_flags_dangerous_methods() -> None:
    findings = [f async for f in ApiMisconfigScanner().scan(_ctx(DangerousMethodsHttp()))]
    methods = [f for f in findings if f.title.startswith("Server advertises")]
    assert len(methods) == 1
    assert methods[0].severity == Severity.LOW
    assert methods[0].cwe == "CWE-16"
    assert "PUT" in methods[0].title and "DELETE" in methods[0].title
    # no XST finding since TRACE was rejected
    assert not [f for f in findings if "Cross-Site Tracing" in f.title]


async def test_scanner_quiet_when_well_configured() -> None:
    findings = [f async for f in ApiMisconfigScanner().scan(_ctx(CleanHttp()))]
    assert [f for f in findings if f.vuln_type == "api-misconfig"] == []
