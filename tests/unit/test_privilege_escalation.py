"""Privilege-escalation forced-browse scanner (BFLA across the identity lattice)."""

from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import urlsplit

from orthrus.core.schemas import Confidence, Severity
from orthrus.scanners import privilege_escalation as pe
from orthrus.scanners.privilege_escalation import PRIVILEGED_PATHS, PrivilegeEscalationScanner


def test_corpus_is_admin_focused():
    assert "/admin/users" in PRIVILEGED_PATHS
    # deliberately excludes ambiguous public-ish routes to stay low-FP
    assert "/users" not in PRIVILEGED_PATHS
    assert "/metrics" not in PRIVILEGED_PATHS


class _Resp:
    def __init__(self, status: int, text: str) -> None:
        self.status_code = status
        self.text = text


class _PrivClient:
    """App where /admin/users is BFLA-broken (any logged-in user reaches it),
    /admin is properly enforced (admin only), all else 404; unknown probe 404."""

    def __init__(self, *a: object, **k: object) -> None:
        pass

    async def get(self, url: str, *, headers: dict | None = None) -> _Resp:
        path = urlsplit(url).path
        cookie = (headers or {}).get("Cookie", "")
        if "/orthrus-privesc-" in path:
            return _Resp(404, "not found")
        if path == "/admin/users":
            if cookie in ("admin", "user"):
                return _Resp(200, "USER MANAGEMENT LIST " + "x" * 80)
            return _Resp(302, "")
        if path == "/admin":
            if cookie == "admin":
                return _Resp(200, "admin home " + "x" * 80)
            if cookie == "user":
                return _Resp(403, "Forbidden")
            return _Resp(302, "")
        return _Resp(404, "nf")

    async def aclose(self) -> None:
        pass


def _ctx(identities: list[dict]) -> SimpleNamespace:
    return SimpleNamespace(
        endpoints=[],
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(identities=identities, timeout=5.0, target="http://h/"),
    )


async def test_flags_bfla_on_unlinked_admin_route(monkeypatch):
    monkeypatch.setattr(pe.httpx, "AsyncClient", _PrivClient)
    ctx = _ctx([
        {"name": "admin", "cookie": "admin"},
        {"name": "user", "cookie": "user"},
        {"name": "anon"},
    ])
    findings = [f async for f in PrivilegeEscalationScanner().scan(ctx)]
    # /admin/users reachable by 'user' (BFLA); /admin enforced (403); anon redirected.
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "privilege-escalation"
    assert f.cwe == "CWE-285"
    assert f.severity == Severity.HIGH
    assert f.confidence == Confidence.FIRM
    assert "/admin/users" in f.title and "user" in f.title


async def test_noop_without_two_identities(monkeypatch):
    monkeypatch.setattr(pe.httpx, "AsyncClient", _PrivClient)
    findings = [f async for f in PrivilegeEscalationScanner().scan(_ctx([{"name": "solo"}]))]
    assert findings == []
