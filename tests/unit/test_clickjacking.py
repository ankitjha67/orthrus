"""Clickjacking scanner + confirmer."""

from __future__ import annotations

import asyncio
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
from orthrus.exploits.clickjacking_confirm import ClickjackingConfirm, build_poc
from orthrus.scanners.clickjacking import (
    ClickjackingScanner,
    frame_ancestors,
    is_frameable,
    is_sensitive_path,
)


# ----------------------------------------------------------------- detectors
def test_frame_ancestors_extraction() -> None:
    assert frame_ancestors("script-src 'self'; frame-ancestors 'none'") == "'none'"
    assert frame_ancestors("default-src 'self'") is None


def test_is_frameable_matrix() -> None:
    assert is_frameable({}) is True  # no protection at all
    assert is_frameable({"X-Frame-Options": "DENY"}) is False
    assert is_frameable({"X-Frame-Options": "SAMEORIGIN"}) is False
    assert is_frameable({"X-Frame-Options": "ALLOW-FROM https://x"}) is True  # deprecated, ignored
    assert is_frameable({"Content-Security-Policy": "frame-ancestors 'none'"}) is False
    assert is_frameable({"Content-Security-Policy": "frame-ancestors 'self'"}) is False
    assert is_frameable({"Content-Security-Policy": "frame-ancestors https://trusted.com"}) is False
    assert is_frameable({"Content-Security-Policy": "frame-ancestors *"}) is True
    # frame-ancestors wins over X-Frame-Options
    assert is_frameable(
        {"X-Frame-Options": "DENY", "Content-Security-Policy": "frame-ancestors *"}
    ) is True


def test_is_sensitive_path() -> None:
    assert is_sensitive_path("/account/settings") is True
    assert is_sensitive_path("/oauth/authorize") is True
    assert is_sensitive_path("/products/42") is False


# ------------------------------------------------------------------- scanner
class FrameHttp:
    def __init__(self, pages: dict[str, tuple[int, dict]]) -> None:
        self.pages = pages

    async def get(self, url: str, **kw: object) -> httpx.Response:
        from urllib.parse import urlsplit

        status, headers = self.pages.get(urlsplit(url).path, (404, {}))
        h = httpx.Headers({"content-type": "text/html", **headers})
        return httpx.Response(status, headers=h, text="<html>page</html>",
                              request=httpx.Request("GET", url))


def _ctx(http: object, endpoints: list[Endpoint]) -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(target="http://h/"),
        endpoints=endpoints,
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        http=http,
    )


def _scan(ctx: SimpleNamespace) -> list[Finding]:
    async def run():
        return [f async for f in ClickjackingScanner().scan(ctx)]

    return asyncio.run(run())


def test_scanner_flags_unprotected_sensitive_page() -> None:
    eps = [Endpoint(url="http://h/login", method=HttpMethod.GET)]
    findings = _scan(_ctx(FrameHttp({"/login": (200, {})}), eps))
    cj = [f for f in findings if f.vuln_type == "clickjacking"]
    assert len(cj) == 1
    assert cj[0].severity == Severity.MEDIUM
    assert cj[0].cwe == "CWE-1021"


def test_scanner_quiet_when_protected() -> None:
    eps = [Endpoint(url="http://h/login", method=HttpMethod.GET)]
    ctx = _ctx(FrameHttp({"/login": (200, {"x-frame-options": "DENY"})}), eps)
    assert [f for f in _scan(ctx) if f.vuln_type == "clickjacking"] == []


# ----------------------------------------------------------------- confirmer
def _finding() -> Finding:
    return Finding(
        vuln_type="clickjacking",
        title="Clickjacking",
        severity=Severity.MEDIUM,
        confidence=Confidence.FIRM,
        url="http://h/login",
        cwe="CWE-1021",
        scanner="clickjacking",
        evidence=Evidence(),
    )


class ConfirmHttp:
    def __init__(self, headers: dict) -> None:
        self.headers = headers

    async def get(self, url: str, **kw: object) -> httpx.Response:
        return httpx.Response(200, headers=httpx.Headers(self.headers), text="<html></html>",
                              request=httpx.Request("GET", url))


def test_build_poc_contains_iframe() -> None:
    poc = build_poc("http://h/login")
    assert "<iframe" in poc and "http://h/login" in poc


def test_confirmer_success_when_still_framable() -> None:
    result = asyncio.run(ClickjackingConfirm().confirm(_ctx(ConfirmHttp({}), []), _finding()))
    assert result.success is True
    assert "<iframe" in (result.extracted_data or "")


def test_confirmer_fails_when_protected() -> None:
    http = ConfirmHttp({"content-security-policy": "frame-ancestors 'none'"})
    result = asyncio.run(ClickjackingConfirm().confirm(_ctx(http, []), _finding()))
    assert result.success is False
