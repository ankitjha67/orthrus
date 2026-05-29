"""NoSQL injection scanner (error-based)."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Endpoint, HttpMethod, Param, ParamLocation, Severity
from orthrus.scanners.nosql import NoSqlInjectionScanner, detect_nosql_error


def test_detect_nosql_error() -> None:
    assert detect_nosql_error("MongoServerError: unknown top level operator: $ne") is True
    assert detect_nosql_error("CastError: Cast to ObjectId failed") is True
    assert detect_nosql_error("user record: guest") is False


class FakeResp:
    def __init__(self, text: str) -> None:
        self.text = text


def _ctx(http: object) -> SimpleNamespace:
    ep = Endpoint(
        url="http://h/nosql?user=guest",
        method=HttpMethod.GET,
        params=[Param(name="user", location=ParamLocation.QUERY, value="guest")],
    )
    return SimpleNamespace(endpoints=[ep], http=http, config=SimpleNamespace(target="http://h/"))


class InjectableHttp:
    """Returns a Mongo error when the value carries operator/quote chars."""

    async def request(self, method: str, url: str, **kw: object) -> FakeResp:
        from urllib.parse import parse_qs, urlsplit

        user = parse_qs(urlsplit(url).query).get("user", [""])[0]
        if any(c in user for c in ("$", "{", "'", '"', "\\")):
            return FakeResp("MongoServerError: unknown top level operator: $ne")
        return FakeResp("user record: ok")


class SafeHttp:
    async def request(self, method: str, url: str, **kw: object) -> FakeResp:
        return FakeResp("user record: ok")


async def test_scanner_flags_nosql_error() -> None:
    findings = [f async for f in NoSqlInjectionScanner().scan(_ctx(InjectableHttp()))]
    nq = [f for f in findings if f.vuln_type == "nosql-injection"]
    assert len(nq) == 1
    assert nq[0].severity == Severity.HIGH
    assert nq[0].cwe == "CWE-943"
    assert nq[0].parameter == "user"


async def test_scanner_quiet_when_no_error() -> None:
    findings = [f async for f in NoSqlInjectionScanner().scan(_ctx(SafeHttp()))]
    assert [f for f in findings if f.vuln_type == "nosql-injection"] == []
