"""HTML-injection scanner + confirmer."""

from __future__ import annotations

import asyncio
import html
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import httpx

from orthrus.core.config import ScopeConfig
from orthrus.core.schemas import (
    Confidence,
    Endpoint,
    Evidence,
    Finding,
    HttpMethod,
    Param,
    ParamLocation,
    Severity,
)
from orthrus.exploits.html_injection_confirm import HtmlInjectionConfirm
from orthrus.scanners.html_injection import HtmlInjectionScanner, html_injection_succeeded
from orthrus.utils.scope import ScopeValidator


# ----------------------------------------------------------------- detector
def test_html_injection_succeeded() -> None:
    assert html_injection_succeeded("<html><u>orthrushiAA</u></html>", "orthrushiAA") == "<u>orthrushiAA"
    # escaped reflection is safe
    assert html_injection_succeeded("<html>&lt;u&gt;orthrushiAA</html>", "orthrushiAA") is None
    assert html_injection_succeeded("nothing here", "orthrushiAA") is None


# ------------------------------------------------------------------- scanner
class ReflectHttp:
    def __init__(self, *, escape: bool) -> None:
        self.escape = escape

    async def request(self, method: str, url: str, **kw: object) -> httpx.Response:
        val = parse_qs(urlsplit(url).query).get("q", [""])[0]
        shown = html.escape(val) if self.escape else val
        body = f"<html><body>Search: {shown}</body></html>"
        return httpx.Response(200, text=body, headers=httpx.Headers({"content-type": "text/html"}),
                              request=httpx.Request(method, url))


def _scan_ctx(http: object) -> SimpleNamespace:
    ep = Endpoint(
        url="http://h/search?q=x",
        method=HttpMethod.GET,
        params=[Param(name="q", location=ParamLocation.QUERY, value="x")],
    )
    return SimpleNamespace(endpoints=[ep], http=http, config=SimpleNamespace(target="http://h/"))


def _scan(ctx: SimpleNamespace) -> list[Finding]:
    async def run():
        return [f async for f in HtmlInjectionScanner().scan(ctx)]

    return asyncio.run(run())


def test_scanner_flags_unescaped_reflection() -> None:
    findings = _scan(_scan_ctx(ReflectHttp(escape=False)))
    hi = [f for f in findings if f.vuln_type == "html-injection"]
    assert len(hi) == 1
    assert hi[0].severity == Severity.MEDIUM
    assert hi[0].cwe == "CWE-79"


def test_scanner_quiet_when_escaped() -> None:
    findings = _scan(_scan_ctx(ReflectHttp(escape=True)))
    assert [f for f in findings if f.vuln_type == "html-injection"] == []


# ----------------------------------------------------------------- confirmer
class ConfirmGetHttp:
    async def get(self, url: str, **kw: object) -> httpx.Response:
        val = parse_qs(urlsplit(url).query).get("q", [""])[0]
        return httpx.Response(200, text=f"<html>{val}</html>",
                              headers=httpx.Headers({"content-type": "text/html"}),
                              request=httpx.Request("GET", url))


def _finding() -> Finding:
    return Finding(
        vuln_type="html-injection",
        title="HTML injection",
        severity=Severity.MEDIUM,
        confidence=Confidence.FIRM,
        url="http://h/search?q=x",
        parameter="q",
        param_location=ParamLocation.QUERY,
        cwe="CWE-79",
        scanner="html-injection",
        evidence=Evidence(),
    )


def _confirm_ctx(http: object) -> SimpleNamespace:
    return SimpleNamespace(
        http=http,
        endpoints=[],
        scope=ScopeValidator(ScopeConfig(domains=["h"], ports=[])),
    )


def test_confirmer_reproduces_reflection() -> None:
    result = asyncio.run(HtmlInjectionConfirm().confirm(_confirm_ctx(ConfirmGetHttp()), _finding()))
    assert result.success is True
    assert "<base href=//" in (result.extracted_data or "")
