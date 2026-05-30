"""Tests for the newly-added confirmation modules: nosql / crlf / cors.

Each confirmer re-sends a probe and upgrades a finding to ``confirmed`` only when
the impact is re-proven (driver error / header survival / origin reflection).
Duck-typed fakes stand in for the HTTP client so the tests stay offline.
"""

from __future__ import annotations

import json as _json
import re
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from orthrus.core.schemas import (
    Endpoint,
    Evidence,
    Finding,
    HttpMethod,
    Param,
    ParamLocation,
    Severity,
)
from orthrus.exploits.cors_confirm import CorsConfirm
from orthrus.exploits.crlf_confirm import CrlfConfirm
from orthrus.exploits.graphql_dos_confirm import GraphqlDosConfirm
from orthrus.exploits.host_header_confirm import HostHeaderConfirm
from orthrus.exploits.idor_confirm import IdorConfirm
from orthrus.exploits.jwt_confirm import JwtConfirm
from orthrus.exploits.mass_assignment_confirm import MassAssignmentConfirm
from orthrus.exploits.nosql_confirm import NoSqlConfirm
from orthrus.exploits.prototype_pollution_confirm import PrototypePollutionConfirm
from orthrus.exploits.registry import EXPLOIT_REGISTRY, exploits_for
from orthrus.scanners.graphql import ALIAS_PROBE_COUNT


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
    for name in (
        "nosql-confirm", "crlf-confirm", "cors-confirm",
        "host-header-confirm", "mass-assignment-confirm", "idor-confirm", "jwt-confirm",
        "prototype-pollution-confirm", "graphql-dos-confirm",
    ):
        assert name in EXPLOIT_REGISTRY


def test_exploits_for_routes_by_vuln_type():
    assert any(e.name == "nosql-confirm" for e in exploits_for(_finding("nosql-injection")))
    assert any(e.name == "crlf-confirm" for e in exploits_for(_finding("crlf-injection")))
    assert any(e.name == "cors-confirm" for e in exploits_for(_finding("cors")))
    assert any(e.name == "host-header-confirm"
               for e in exploits_for(_finding("host-header-injection")))
    assert any(e.name == "mass-assignment-confirm"
               for e in exploits_for(_finding("mass-assignment")))
    assert any(e.name == "idor-confirm" for e in exploits_for(_finding("idor")))
    assert any(e.name == "jwt-confirm" for e in exploits_for(_finding("jwt")))


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


# ----------------------------------------------------------------- host-header-confirm
class _HostHttp:
    def __init__(self, *, reflect: bool) -> None:
        self._reflect = reflect

    async def get(self, url: str, *, headers: dict | None = None,
                  follow_redirects: bool = True) -> _Resp:
        host = (headers or {}).get("X-Forwarded-Host") or (headers or {}).get("Host", "")
        if self._reflect and host:
            return _Resp(text=f'<a href="https://{host}/reset?token=abc">reset</a>')
        return _Resp(text="<a href='/relative/link'>x</a>")


async def test_host_header_confirm_success_on_reflection():
    ctx = SimpleNamespace(http=_HostHttp(reflect=True))
    res = await HostHeaderConfirm().confirm(ctx, _finding("host-header-injection", url="http://h/"))
    assert res.success is True
    assert res.extracted_data.startswith("orthrus-hhi-")


async def test_host_header_confirm_fail_without_reflection():
    ctx = SimpleNamespace(http=_HostHttp(reflect=False))
    res = await HostHeaderConfirm().confirm(ctx, _finding("host-header-injection", url="http://h/"))
    assert res.success is False


# ----------------------------------------------------------------- mass-assignment-confirm
class _MassHttp:
    def __init__(self, *, reflect: bool) -> None:
        self._reflect = reflect

    async def request(self, method: str, url: str, *, json: dict | None = None,
                      data: dict | None = None, follow_redirects: bool = True) -> _Resp:
        body = json if json is not None else (data or {})
        # Vulnerable server echoes the whole submitted body back into its object.
        return _Resp(text=_json.dumps(body) if self._reflect else '{"ok":true}')


def _mass_ctx(reflect: bool) -> SimpleNamespace:
    ep = Endpoint(
        url="http://h/api/users",
        method=HttpMethod.POST,
        params=[Param(name="username", location=ParamLocation.BODY, value="bob")],
    )
    return SimpleNamespace(http=_MassHttp(reflect=reflect), endpoints=[ep])


async def test_mass_assignment_confirm_success_when_field_bound():
    f = _finding("mass-assignment", url="http://h/api/users", param_location=ParamLocation.BODY)
    res = await MassAssignmentConfirm().confirm(_mass_ctx(reflect=True), f)
    assert res.success is True
    assert "role" in res.extracted_data  # a privileged field was reproduced


async def test_mass_assignment_confirm_fail_when_nothing_bound():
    f = _finding("mass-assignment", url="http://h/api/users", param_location=ParamLocation.BODY)
    res = await MassAssignmentConfirm().confirm(_mass_ctx(reflect=False), f)
    assert res.success is False


# ----------------------------------------------------------------- idor-confirm
class _IdorHttp:
    """Distinct per-id objects for small ids; 404 for implausible ids (or a
    catch-all page for every id when not enumerable)."""

    def __init__(self, *, enumerable: bool) -> None:
        self._enumerable = enumerable

    async def get(self, url: str, *, follow_redirects: bool = True) -> _Resp:
        ident = int(parse_qs(urlsplit(url).query).get("id", ["0"])[0])
        if not self._enumerable:
            return _Resp(text="welcome to the catch-all page " + "." * 60)
        if ident > 100_000:
            return _Resp(text="not found", status_code=404)
        return _Resp(text=f"user record #{ident} " + "x" * 60)


def _idor_finding() -> Finding:
    return _finding(
        "idor", url="http://h/item?id=5", parameter="id",
        param_location=ParamLocation.QUERY, evidence=Evidence(request_raw="id=5"),
    )


async def test_idor_confirm_success_on_enumerable_space():
    ctx = SimpleNamespace(http=_IdorHttp(enumerable=True), endpoints=[])
    res = await IdorConfirm().confirm(ctx, _idor_finding())
    assert res.success is True
    assert res.technique == "object-enumeration replay"


async def test_idor_confirm_fail_on_catchall_page():
    ctx = SimpleNamespace(http=_IdorHttp(enumerable=False), endpoints=[])
    res = await IdorConfirm().confirm(ctx, _idor_finding())
    assert res.success is False


# ----------------------------------------------------------------- jwt-confirm
def _jwt_ctx_with_token(token: str) -> SimpleNamespace:
    return SimpleNamespace(
        http=SimpleNamespace(session=None),
        config=SimpleNamespace(extra_headers={"Authorization": f"Bearer {token}"}),
        endpoints=[],
    )


async def test_jwt_confirm_forges_with_weak_secret():
    pyjwt = pytest.importorskip("jwt")
    token = pyjwt.encode({"user": "bob"}, "secret", algorithm="HS256")
    f = _finding(
        "jwt", title="JWT signed with a weak/guessable secret ('secret')",
        evidence=Evidence(matched_at=token[:24] + "..."),
    )
    res = await JwtConfirm().confirm(_jwt_ctx_with_token(token), f)
    assert res.success is True
    assert res.extracted_data == "forged-token-verified"
    assert "secret" not in (res.evidence.notes or "").lower() or "recovered" in res.evidence.notes


async def test_jwt_confirm_skips_non_weak_secret_findings():
    pytest.importorskip("jwt")
    f = _finding("jwt", title="JWT uses the 'none' algorithm",
                 evidence=Evidence(matched_at="eyJabc..."))
    res = await JwtConfirm().confirm(_jwt_ctx_with_token("eyJabc"), f)
    assert res.success is False


# ----------------------------------------------------------------- prototype-pollution-confirm
class _PPHttp:
    """Simulates a polluted prototype: once __proto__.<sentinel> is set, benign
    requests start echoing the sentinel (when vulnerable)."""

    def __init__(self, *, vulnerable: bool) -> None:
        self._vulnerable = vulnerable
        self._polluted: set[str] = set()

    async def request(self, method: str, url: str, *, json: dict | None = None,
                      follow_redirects: bool = True) -> _Resp:
        body = json or {}
        for key in ("__proto__", "constructor"):
            if key in body:
                sub = body[key].get("prototype", {}) if key == "constructor" else body[key]
                self._polluted.update(sub)
        text = " ".join(sorted(self._polluted)) if self._vulnerable else "clean"
        return _Resp(text=text)


async def test_prototype_pollution_confirm_success_on_persistence():
    ctx = SimpleNamespace(http=_PPHttp(vulnerable=True))
    res = await PrototypePollutionConfirm().confirm(ctx, _finding("prototype-pollution", url="http://h/api/merge"))
    assert res.success is True
    assert res.extracted_data.startswith("orthrusPP")


async def test_prototype_pollution_confirm_fail_when_not_persisted():
    ctx = SimpleNamespace(http=_PPHttp(vulnerable=False))
    res = await PrototypePollutionConfirm().confirm(ctx, _finding("prototype-pollution", url="http://h/api/merge"))
    assert res.success is False


# ----------------------------------------------------------------- graphql-dos-confirm
class _GqlHttp:
    def __init__(self, *, ok: bool) -> None:
        self._ok = ok

    async def post(self, url: str, *, json: object = None,
                   follow_redirects: bool = False) -> _Resp:
        if isinstance(json, list):  # batch probe
            return _Resp('[{"data":{"__typename":"Q"}},{"data":{"__typename":"Q"}}]'
                         if self._ok else '{"errors":[]}')
        query = json.get("query", "") if isinstance(json, dict) else ""
        if "orthrusAlias" in query and self._ok:
            body = ",".join(f'"orthrusAlias{i}":"Q"' for i in range(ALIAS_PROBE_COUNT))
            return _Resp('{"data":{' + body + "}}")
        return _Resp('{"errors":[{"message":"too complex"}]}')


async def test_graphql_dos_confirm_batching():
    ctx = SimpleNamespace(http=_GqlHttp(ok=True))
    f = _finding("graphql-dos", title="GraphQL query batching enabled", url="http://h/graphql")
    res = await GraphqlDosConfirm().confirm(ctx, f)
    assert res.success is True
    assert res.technique == "query-batching replay"


async def test_graphql_dos_confirm_alias_overloading():
    ctx = SimpleNamespace(http=_GqlHttp(ok=True))
    f = _finding("graphql-dos", title="GraphQL alias overloading (no query-cost limit)",
                 url="http://h/graphql")
    res = await GraphqlDosConfirm().confirm(ctx, f)
    assert res.success is True
    assert res.technique == "alias-overloading replay"


async def test_graphql_dos_confirm_fail_when_not_amplified():
    ctx = SimpleNamespace(http=_GqlHttp(ok=False))
    f = _finding("graphql-dos", title="GraphQL query batching enabled", url="http://h/graphql")
    res = await GraphqlDosConfirm().confirm(ctx, f)
    assert res.success is False
