"""XPath injection scanner (error-based)."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Endpoint, HttpMethod, Param, ParamLocation, Severity
from orthrus.scanners.xpath import XPathInjectionScanner, detect_xpath_error


def test_detect_xpath_error() -> None:
    assert detect_xpath_error("javax.xml.xpath.XPathExpressionException") is True
    assert detect_xpath_error("Warning: SimpleXMLElement::xpath(): Invalid expression") is True
    assert detect_xpath_error("lxml.etree.XPathEvalError: Invalid expression") is True
    assert detect_xpath_error("results: 2 matching nodes") is False


class FakeResp:
    def __init__(self, text: str) -> None:
        self.text = text


def _ctx(http: object) -> SimpleNamespace:
    ep = Endpoint(
        url="http://h/search?q=guest",
        method=HttpMethod.GET,
        params=[Param(name="q", location=ParamLocation.QUERY, value="guest")],
    )
    return SimpleNamespace(endpoints=[ep], http=http, config=SimpleNamespace(target="http://h/"))


class InjectableHttp:
    """Returns an XPath error when the value carries expression metacharacters."""

    async def request(self, method: str, url: str, **kw: object) -> FakeResp:
        from urllib.parse import parse_qs, urlsplit

        q = parse_qs(urlsplit(url).query).get("q", [""])[0]
        if any(c in q for c in ("'", '"', "]", ")")):
            return FakeResp("Warning: SimpleXMLElement::xpath(): Invalid expression in /var/www")
        return FakeResp("search results")


class SafeHttp:
    async def request(self, method: str, url: str, **kw: object) -> FakeResp:
        return FakeResp("search results")


async def test_scanner_flags_xpath_error() -> None:
    findings = [f async for f in XPathInjectionScanner().scan(_ctx(InjectableHttp()))]
    hits = [f for f in findings if f.vuln_type == "xpath-injection"]
    assert len(hits) == 1
    assert hits[0].severity == Severity.HIGH
    assert hits[0].cwe == "CWE-643"
    assert hits[0].parameter == "q"


async def test_scanner_quiet_when_no_error() -> None:
    findings = [f async for f in XPathInjectionScanner().scan(_ctx(SafeHttp()))]
    assert [f for f in findings if f.vuln_type == "xpath-injection"] == []
