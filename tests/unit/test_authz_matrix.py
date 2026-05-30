"""Multi-identity authorization matrix (BOLA/BFLA) + Identity model."""

from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import urlsplit

from orthrus.core.identity import Identity, identity_headers, parse_identities
from orthrus.core.schemas import Confidence, Endpoint, HttpMethod, Param, ParamLocation
from orthrus.scanners import authz_matrix as am
from orthrus.scanners.authz_matrix import AuthorizationMatrixScanner, authz_verdict, is_object_ref


# --------------------------------------------------------------- identity model
def test_parse_identities_from_dicts():
    ids = parse_identities([
        {"name": "admin", "cookie": "session=a"},
        {"name": "user", "token": "tok123"},
        {"name": "anon"},
    ])
    assert [i.name for i in ids] == ["admin", "user", "anon"]
    assert ids[0].is_authenticated and ids[1].is_authenticated
    assert ids[2].is_authenticated is False


def test_parse_identities_from_json_string_and_garbage():
    assert [i.name for i in parse_identities('[{"name":"x","cookie":"c"}]')] == ["x"]
    assert parse_identities("not json") == []
    assert parse_identities({"not": "a list"}) == []


def test_identity_headers_cookie_token_anon():
    assert identity_headers(Identity("a", cookie="s=1"))["Cookie"] == "s=1"
    assert identity_headers(Identity("a", token="t"))["Authorization"] == "Bearer t"
    assert identity_headers(Identity("anon")) == {}


# --------------------------------------------------------------- authz_verdict
def test_verdict_bypass_on_same_success():
    assert authz_verdict(200, "X" * 100, 200, "X" * 100) == "bypass"


def test_verdict_enforced_on_forbidden_and_redirect_and_marker():
    assert authz_verdict(200, "X" * 100, 403, "") == "enforced"
    assert authz_verdict(200, "X" * 100, 302, "") == "enforced"
    assert authz_verdict(200, "X" * 100, 200, "Access Denied") == "enforced"


def test_verdict_ambiguous_on_different_status_or_size():
    assert authz_verdict(200, "X" * 100, 404, "nf") == "ambiguous"
    assert authz_verdict(200, "X" * 100, 200, "Y" * 10) == "ambiguous"


# --------------------------------------------------------------- classification
def test_is_object_ref():
    assert is_object_ref("http://h/doc/1", []) is True
    assert is_object_ref("http://h/u/550e8400-e29b-41d4-a716-446655440000", []) is True
    assert is_object_ref("http://h/items", [Param(name="id", location=ParamLocation.QUERY)]) is True
    assert is_object_ref("http://h/dashboard", []) is False


# --------------------------------------------------------------- full scan flow
class _FakeResp:
    def __init__(self, status: int, text: str) -> None:
        self.status_code = status
        self.text = text


class _FakeClient:
    """Multi-tenant app: /doc/1 is BOLA-broken (any logged-in user reads it);
    /admin is properly enforced (only admin); anonymous is redirected."""

    def __init__(self, *a: object, **k: object) -> None:
        pass

    async def request(self, method: str, url: str, *, headers: dict | None = None) -> _FakeResp:
        cookie = (headers or {}).get("Cookie", "")
        path = urlsplit(url).path
        if path == "/doc/1":
            if cookie in ("admin", "user"):  # BOLA: user wrongly reads admin's doc
                return _FakeResp(200, "SECRET DOC " + "x" * 80)
            return _FakeResp(302, "")  # anon redirected to login
        if path == "/admin":
            if cookie == "admin":
                return _FakeResp(200, "ADMIN PANEL " + "x" * 80)
            if cookie == "user":
                return _FakeResp(403, "Forbidden")
            return _FakeResp(302, "")
        return _FakeResp(404, "nf")

    async def aclose(self) -> None:
        pass


def _ctx(identities: list[dict]) -> SimpleNamespace:
    eps = [
        Endpoint(url="http://h/doc/1", method=HttpMethod.GET),
        Endpoint(url="http://h/admin", method=HttpMethod.GET),
    ]
    return SimpleNamespace(
        endpoints=eps,
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(
            identities=identities, timeout=5.0
        ),
    )


async def test_scan_flags_bola_not_enforced(monkeypatch):
    monkeypatch.setattr(am.httpx, "AsyncClient", _FakeClient)
    ctx = _ctx([
        {"name": "admin", "cookie": "admin"},
        {"name": "user", "cookie": "user"},
        {"name": "anon"},
    ])
    findings = [f async for f in AuthorizationMatrixScanner().scan(ctx)]
    # /doc/1 leaks to 'user' (BOLA, firm); /admin is enforced; anon is redirected.
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "broken-authorization"
    assert f.cwe == "CWE-639"  # object-ref path -> BOLA
    assert f.confidence == Confidence.FIRM  # a *named* user got the data
    assert "user" in f.title and "/doc/1" in (f.evidence.request_raw or "")


async def test_scan_noop_without_two_identities(monkeypatch):
    monkeypatch.setattr(am.httpx, "AsyncClient", _FakeClient)
    findings = [f async for f in AuthorizationMatrixScanner().scan(_ctx([{"name": "solo"}]))]
    assert findings == []
