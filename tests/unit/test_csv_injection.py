"""CSV / formula-injection scanner (OWASP "CSV injection")."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Endpoint, HttpMethod, Param, ParamLocation, Severity
from orthrus.scanners.csv_injection import (
    CsvInjectionScanner,
    formula_survived,
    make_payload,
)


def test_make_payload_is_benign_formula() -> None:
    payload = make_payload()
    assert payload.startswith("=1+orthrus")
    # Two calls carry distinct nonces.
    assert make_payload() != make_payload()


def test_formula_survived_positive() -> None:
    payload = "=1+orthrusabc123"
    body = f"name,value\nbob,{payload}\n"
    assert formula_survived("text/csv; charset=utf-8", body, payload) is True
    assert formula_survived("application/vnd.ms-excel", body, payload) is True
    assert formula_survived("application/vnd.openxmlformats...spreadsheetml.sheet", body, payload) is True


def test_formula_survived_wrong_content_type() -> None:
    payload = "=1+orthrusabc123"
    body = f"<html><td>{payload}</td></html>"
    # Reflected into HTML, not a spreadsheet export -> not exploitable here.
    assert formula_survived("text/html; charset=utf-8", body, payload) is False
    assert formula_survived(None, body, payload) is False


def test_formula_survived_escaped_breaks_payload() -> None:
    payload = "=1+orthrusabc123"
    # A real sanitizer strips/replaces the leading trigger, so the payload no
    # longer appears verbatim -> not flagged.
    assert formula_survived("text/csv", "name,value\nbob,1+orthrusabc123\n", payload) is False
    assert formula_survived("text/csv", "name,value\nbob,&#61;1+orthrusabc123\n", payload) is False


def test_formula_survived_absent_or_no_trigger() -> None:
    payload = "=1+orthrusabc123"
    # Payload absent entirely.
    assert formula_survived("text/csv", "name,value\nbob,plain\n", payload) is False
    # Payload itself does not start with a trigger char.
    assert formula_survived("text/csv", "1+orthrusabc123", "1+orthrusabc123") is False


class FakeResp:
    def __init__(self, text: str, content_type: str | None) -> None:
        self.text = text
        self.status_code = 200
        self.headers = {"content-type": content_type or ""}
        self.content_type = content_type


class CsvExportHttp:
    """Reflects the injected query value into a CSV export (vulnerable)."""

    async def request(self, method: str, url: str, **kw: object) -> FakeResp:
        from urllib.parse import parse_qs, urlsplit

        value = parse_qs(urlsplit(url).query).get("q", [""])[0]
        return FakeResp(f"id,q\n1,{value}\n", "text/csv; charset=utf-8")


class HtmlEchoHttp:
    """Reflects the value but only into an HTML page (not exploitable)."""

    async def request(self, method: str, url: str, **kw: object) -> FakeResp:
        from urllib.parse import parse_qs, urlsplit

        value = parse_qs(urlsplit(url).query).get("q", [""])[0]
        return FakeResp(f"<html><body>{value}</body></html>", "text/html")


def _ctx(http: object) -> SimpleNamespace:
    ep = Endpoint(
        url="http://h/export?q=hello",
        method=HttpMethod.GET,
        params=[Param(name="q", location=ParamLocation.QUERY, value="hello")],
    )
    return SimpleNamespace(
        endpoints=[ep],
        http=http,
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(target="http://h/"),
    )


async def test_scanner_flags_csv_export() -> None:
    findings = [f async for f in CsvInjectionScanner().scan(_ctx(CsvExportHttp()))]
    fi = [f for f in findings if f.vuln_type == "formula-injection"]
    assert len(fi) == 1
    assert fi[0].severity == Severity.MEDIUM
    assert fi[0].cwe == "CWE-1236"
    assert fi[0].parameter == "q"
    assert fi[0].param_location == ParamLocation.QUERY
    assert fi[0].evidence.request_raw.startswith("q==1+orthrus")


async def test_scanner_quiet_on_html() -> None:
    findings = [f async for f in CsvInjectionScanner().scan(_ctx(HtmlEchoHttp()))]
    assert [f for f in findings if f.vuln_type == "formula-injection"] == []
