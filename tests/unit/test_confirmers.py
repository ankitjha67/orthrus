"""Tests for the newly-added confirmation modules: nosql / crlf / cors.

Each confirmer re-sends a probe and upgrades a finding to ``confirmed`` only when
the impact is re-proven (driver error / header survival / origin reflection).
Duck-typed fakes stand in for the HTTP client so the tests stay offline.
"""

from __future__ import annotations

import re
from types import SimpleNamespace

from orthrus.core.schemas import Evidence, Finding, ParamLocation, Severity
from orthrus.exploits.cors_confirm import CorsConfirm
from orthrus.exploits.crlf_confirm import CrlfConfirm
from orthrus.exploits.nosql_confirm import NoSqlConfirm
from orthrus.exploits.registry import EXPLOIT_REGISTRY, exploits_for


def _finding(vuln_type: str, **kw: object) -> Finding:
    base: dict = {
        "vuln_type": vuln_type,
        "title": f"{vuln_type} finding",
        "severity": Severity.HIGH,
        "url": "http://h/x",
    }
    base.update(kw)
    return Finding(**base)


class _Req:
    method = "GET"
    url = "http://h/x"
    headers: dict = {}


class _Resp:
    def __init__(self, text: str = "", headers: dict | None = None, status_code: int = 200) -> None:
        self.text = text
        self.headers = headers or {}
        self.status_code = status_code
        self.http_version = "HTTP/1.1"
        self.request = _Req()


# ----------------------------------------------------------------- registration
def test_new_confirmers_registered():
    for name in ("nosql-confirm", "crlf-confirm", "cors-confirm"):
        assert name in EXPLOIT_REGISTRY


def test_exploits_for_routes_by_vuln_type():
    assert any(e.name == "nosql-confirm" for e in exploits_for(_finding("nosql-injection")))
    assert any(e.name == "crlf-confirm" for e in exploits_for(_finding("crlf-injection")))
    assert any(e.name == "cors-confirm" for e in exploits_for(_finding("cors")))


# ----------------------------------------------------------------- nosql-confirm
class _NoSqlHttp:
    def __init__(self, body: str) -> None:
        self._body = body

    async def get(self, url: str, *, follow_redirects: bool = True) -> _Resp:
        return _Resp(text=self._body)


async def test_nosql_confirm_success_on_driver_error():
    ctx = SimpleNamespace(http=_NoSqlHttp("MongoServerError: unknown top level operator: $gt"),
                          endpoints=[])
    f = _finding("nosql-injection", parameter="user", evidence=Evidence(request_raw="user=' "))
    res = await NoSqlConfirm().confirm(ctx, f)
    assert res.success is True
    assert res.technique == "error-based replay"


async def test_nosql_confirm_fail_without_error():
    ctx = SimpleNamespace(http=_NoSqlHttp("welcome, guest"), endpoints=[])
    f = _finding("nosql-injection", parameter="user", evidence=Evidence(request_raw="user=' "))
    res = await NoSqlConfirm().confirm(ctx, f)
    assert res.success is False


# ----------------------------------------------------------------- crlf-confirm
class _CrlfHttp:
    """Echoes the injected nonce back into a response header (vulnerable) or not."""

    def __init__(self, *, vulnerable: bool) -> None:
        self._vulnerable = vulnerable

    async def get(self, url: str, *, follow_redirects: bool = True) -> _Resp:
        if not self._vulnerable:
            return _Resp(headers={"Content-Type": "text/html"})
        m = re.search(r"ocrlf[a-f0-9]{10}", url)
        nonce = m.group(0) if m else "missing"
        return _Resp(headers={"X-Orthrus-Crlf": nonce, "Set-Cookie": f"ocrlf={nonce}"})


async def test_crlf_confirm_success_when_header_survives():
    ctx = SimpleNamespace(http=_CrlfHttp(vulnerable=True), endpoints=[])
    f = _finding("crlf-injection", parameter="q", param_location=ParamLocation.QUERY)
    res = await CrlfConfirm().confirm(ctx, f)
    assert res.success is True
    assert "fresh nonce" in res.technique


async def test_crlf_confirm_fail_when_header_absent():
    ctx = SimpleNamespace(http=_CrlfHttp(vulnerable=False), endpoints=[])
    f = _finding("crlf-injection", parameter="q", param_location=ParamLocation.QUERY)
    res = await CrlfConfirm().confirm(ctx, f)
    assert res.success is False


# ----------------------------------------------------------------- cors-confirm
class _CorsHttp:
    """Reflects the request Origin into ACAO when vulnerable."""

    def __init__(self, *, reflect: bool, credentials: bool = True) -> None:
        self._reflect = reflect
        self._credentials = credentials

    async def get(self, url: str, *, headers: dict | None = None,
                  follow_redirects: bool = True) -> _Resp:
        origin = (headers or {}).get("Origin", "")
        if not self._reflect:
            return _Resp(headers={"Access-Control-Allow-Origin": "https://trusted.example"})
        h = {"Access-Control-Allow-Origin": origin}
        if self._credentials:
            h["Access-Control-Allow-Credentials"] = "true"
        return _Resp(headers=h)


async def test_cors_confirm_success_on_fresh_origin_reflection():
    ctx = SimpleNamespace(http=_CorsHttp(reflect=True, credentials=True))
    f = _finding("cors", url="http://h/api")
    res = await CorsConfirm().confirm(ctx, f)
    assert res.success is True
    assert "credentials" in (res.evidence.notes or "")


async def test_cors_confirm_fail_when_origin_not_reflected():
    ctx = SimpleNamespace(http=_CorsHttp(reflect=False))
    f = _finding("cors", url="http://h/api")
    res = await CorsConfirm().confirm(ctx, f)
    assert res.success is False
