"""Host-header injection / password-reset poisoning scanner.

Covers the pure reflection detectors (precise enough to avoid substring false
positives) and drives the scanner against duck-typed fakes for the positive
(body-reflection and redirect-Location) and negative paths.
"""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Severity
from orthrus.scanners.host_header import (
    SENTINEL,
    HostHeaderInjectionScanner,
    host_reflected_in_location,
    host_reflected_in_url,
)


# ------------------------------------------------------------ pure detectors
def test_host_reflected_in_url_matches_absolute_url_authority() -> None:
    assert host_reflected_in_url(f'<a href="https://{SENTINEL}/reset?t=1">x</a>') is True
    assert host_reflected_in_url(f'<link href="//{SENTINEL}/s.css">') is True
    assert host_reflected_in_url(f"redirect to http://{SENTINEL}") is True


def test_host_reflected_in_url_rejects_substring_and_longer_host() -> None:
    # Sentinel as a longer host (suffix attack guard) must NOT match.
    assert host_reflected_in_url(f"https://{SENTINEL}.evil.com/x") is False
    # Bare mention in text (not a URL authority) must NOT match.
    assert host_reflected_in_url(f"your host is {SENTINEL} today") is False
    assert host_reflected_in_url("nothing here") is False


def test_host_reflected_in_location() -> None:
    assert host_reflected_in_location(f"https://{SENTINEL}/dashboard") is True
    assert host_reflected_in_location(f"//{SENTINEL}/x") is True
    assert host_reflected_in_location("/local/path") is False
    assert host_reflected_in_location(f"https://{SENTINEL}.evil.com/x") is False
    assert host_reflected_in_location("") is False


# ------------------------------------------------------------ scanner harness
class FakeResp:
    def __init__(self, text: str = "", headers: dict[str, str] | None = None) -> None:
        self.text = text
        self.headers = headers or {}


def _ctx(http: object, endpoints: list[str] | None = None) -> SimpleNamespace:
    eps = [SimpleNamespace(url=u) for u in (endpoints or [])]
    return SimpleNamespace(
        config=SimpleNamespace(target="http://h/"),
        endpoints=eps,
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        http=http,
    )


class ReflectingHttp:
    """Reflects a forged host into an absolute URL when the header is present."""

    async def get(self, url: str, headers: dict[str, str] | None = None, **kw: object) -> FakeResp:
        h = headers or {}
        if SENTINEL in (h.get("X-Forwarded-Host", ""), h.get("Host", "")):
            return FakeResp(text=f'<a href="https://{SENTINEL}/reset?token=x">reset</a>')
        return FakeResp(text="<html>ok</html>")


class RedirectHttp:
    """Reflects the forged host into the redirect Location header."""

    async def get(self, url: str, headers: dict[str, str] | None = None, **kw: object) -> FakeResp:
        return FakeResp(text="", headers={"location": f"https://{SENTINEL}/next"})


class SafeHttp:
    """Never reflects the forged host -> no finding."""

    async def get(self, url: str, headers: dict[str, str] | None = None, **kw: object) -> FakeResp:
        return FakeResp(text="<html>welcome to example.com</html>", headers={"location": "/home"})


async def test_scanner_flags_reflection_in_body() -> None:
    findings = [f async for f in HostHeaderInjectionScanner().scan(_ctx(ReflectingHttp()))]
    hhi = [f for f in findings if f.vuln_type == "host-header-injection"]
    assert len(hhi) == 1
    assert hhi[0].severity == Severity.MEDIUM
    assert hhi[0].cwe == "CWE-644"


async def test_scanner_flags_reflection_in_location() -> None:
    findings = [f async for f in HostHeaderInjectionScanner().scan(_ctx(RedirectHttp()))]
    assert len([f for f in findings if f.vuln_type == "host-header-injection"]) == 1


async def test_scanner_no_finding_when_host_not_reflected() -> None:
    findings = [f async for f in HostHeaderInjectionScanner().scan(_ctx(SafeHttp()))]
    assert [f for f in findings if f.vuln_type == "host-header-injection"] == []


async def test_scanner_emits_one_finding_per_host() -> None:
    # Two endpoints on the SAME host -> deduped to a single finding.
    ctx = _ctx(ReflectingHttp(), endpoints=["http://h/a", "http://h/b"])
    findings = [f async for f in HostHeaderInjectionScanner().scan(ctx)]
    assert len([f for f in findings if f.vuln_type == "host-header-injection"]) == 1
