"""CRLF injection / HTTP response splitting scanner."""

from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

from orthrus.core.schemas import Endpoint, HttpMethod, Param, ParamLocation, Severity
from orthrus.scanners.crlf import CrlfInjectionScanner, crlf_injected


def test_crlf_injected_detector() -> None:
    assert crlf_injected([("X-Orthrus-Crlf", "abc123")], "abc123") is True
    assert crlf_injected([("set-cookie", "ocrlf=abc123")], "abc123") is True
    assert crlf_injected([("location", "/home")], "abc123") is False


class FakeResp:
    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers
        self.text = ""
        self.status_code = 302


def _ctx(http: object) -> SimpleNamespace:
    ep = Endpoint(
        url="http://h/redirect?url=/x",
        method=HttpMethod.GET,
        params=[Param(name="url", location=ParamLocation.QUERY, value="/x")],
    )
    return SimpleNamespace(endpoints=[ep], http=http, config=SimpleNamespace(target="http://h/"))


class SplittingHttp:
    """Reflects an injected CRLF header (vulnerable server)."""

    async def request(self, method: str, url: str, follow_redirects: bool = True, **kw: object) -> FakeResp:
        for val in parse_qs(urlsplit(url).query).values():
            v = val[0]
            if "\r\n" in v and "X-Orthrus-Crlf:" in v:
                nonce = v.split("X-Orthrus-Crlf:")[1].split("\r\n")[0].strip()
                return FakeResp({"x-orthrus-crlf": nonce, "location": "/x"})
        return FakeResp({"location": "/x"})


class SafeHttp:
    async def request(self, method: str, url: str, follow_redirects: bool = True, **kw: object) -> FakeResp:
        return FakeResp({"location": "/x"})  # newlines stripped -> no injected header


async def test_scanner_flags_response_split() -> None:
    findings = [f async for f in CrlfInjectionScanner().scan(_ctx(SplittingHttp()))]
    crlf = [f for f in findings if f.vuln_type == "crlf-injection"]
    assert len(crlf) == 1
    assert crlf[0].severity == Severity.MEDIUM
    assert crlf[0].cwe == "CWE-113"


async def test_scanner_quiet_when_newlines_stripped() -> None:
    findings = [f async for f in CrlfInjectionScanner().scan(_ctx(SafeHttp()))]
    assert [f for f in findings if f.vuln_type == "crlf-injection"] == []
