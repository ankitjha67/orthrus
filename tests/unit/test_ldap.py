"""LDAP injection scanner (error-based)."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Endpoint, HttpMethod, Param, ParamLocation, Severity
from orthrus.scanners.ldap import LdapInjectionScanner, detect_ldap_error


def test_detect_ldap_error() -> None:
    assert detect_ldap_error("javax.naming.directory.InvalidSearchFilterException") is True
    assert detect_ldap_error("Warning: ldap_search(): Bad search filter") is True
    assert detect_ldap_error("AcceptSecurityContext error, data 52e, DSID-0C09042F") is True
    assert detect_ldap_error("directory listing: 3 users found") is False


class FakeResp:
    def __init__(self, text: str) -> None:
        self.text = text


def _ctx(http: object) -> SimpleNamespace:
    ep = Endpoint(
        url="http://h/login?user=guest",
        method=HttpMethod.GET,
        params=[Param(name="user", location=ParamLocation.QUERY, value="guest")],
    )
    return SimpleNamespace(endpoints=[ep], http=http, config=SimpleNamespace(target="http://h/"))


class InjectableHttp:
    """Returns an LDAP error when the value carries filter metacharacters."""

    async def request(self, method: str, url: str, **kw: object) -> FakeResp:
        from urllib.parse import parse_qs, urlsplit

        user = parse_qs(urlsplit(url).query).get("user", [""])[0]
        if any(c in user for c in ("*", "(", ")", "\\")):
            return FakeResp("javax.naming.directory.InvalidSearchFilterException: bad search filter")
        return FakeResp("login page")


class SafeHttp:
    async def request(self, method: str, url: str, **kw: object) -> FakeResp:
        return FakeResp("login page")


async def test_scanner_flags_ldap_error() -> None:
    findings = [f async for f in LdapInjectionScanner().scan(_ctx(InjectableHttp()))]
    hits = [f for f in findings if f.vuln_type == "ldap-injection"]
    assert len(hits) == 1
    assert hits[0].severity == Severity.HIGH
    assert hits[0].cwe == "CWE-90"
    assert hits[0].parameter == "user"


async def test_scanner_quiet_when_no_error() -> None:
    findings = [f async for f in LdapInjectionScanner().scan(_ctx(SafeHttp()))]
    assert [f for f in findings if f.vuln_type == "ldap-injection"] == []
