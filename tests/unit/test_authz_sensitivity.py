"""Sensitive-data evidence + authz severity escalation.

Covers the sensitivity detector (precision + redaction) and the three new
authz-matrix behaviours it drives: BOLA leaking PII/money escalates to CRITICAL
with redacted evidence, an anonymous control suppresses public-page false
positives, and sensitive data reachable anonymously is reported as missing
authentication (CWE-306).
"""

from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import urlsplit

from orthrus.core.schemas import Confidence, Endpoint, HttpMethod, Severity
from orthrus.scanners import authz_matrix as am
from orthrus.scanners.authz_matrix import AuthorizationMatrixScanner, is_public
from orthrus.utils.sensitivity import describe, has_high_value, scan_sensitive


# --------------------------------------------------------------- sensitivity detector
def test_detects_high_value_classes():
    body = (
        '{"email":"john.doe@corp.example","token":"eyJhbGciOiJIUzI1NiJ9.eyJ1IjoxfQ.abcdefghij",'
        '"iban":"DE89370400440532013000","balance":"USD 4200.00","card":"4111 1111 1111 1111"}'
    )
    kinds = {h.kind for h in scan_sensitive(body)}
    assert {"email", "jwt", "iban", "money", "payment-card"} <= kinds
    assert has_high_value(scan_sensitive(body)) is True


def test_email_is_redacted_not_leaked():
    (hit,) = [h for h in scan_sensitive("contact alice@bank.example now") if h.kind == "email"]
    assert hit.sample == "a***@***.example" and "alice" not in hit.sample


def test_luhn_rejects_non_card_digit_runs():
    # 16 sequential digits that fail the Luhn check must NOT be reported as a card.
    assert [h for h in scan_sensitive("ref 1234567890123456 end") if h.kind == "payment-card"] == []


def test_public_marketing_copy_has_no_hits():
    assert scan_sensitive("<html>Welcome! Play casino games and claim your bonus today.</html>") == []
    assert has_high_value([]) is False


# ------------------------------------------------------------------- is_public
def test_is_public_only_when_anon_gets_equivalent_success():
    assert is_public(200, "same body here", 200, "same body here") is True
    assert is_public(403, "", 200, "x") is False           # anon forbidden
    assert is_public(302, "", 200, "x") is False           # anon redirected to login
    assert is_public(200, "Access Denied", 200, "x") is False  # deny marker
    assert is_public(200, "y" * 200, 200, "x") is False    # bodies differ materially


# --------------------------------------------------------------- authz scan flows
_SENSITIVE = '{"user":"alice","email":"alice@corp.example","balance":"USD 4200.00"}' + " " * 40
_PRIVATE_PLAIN = "Dashboard widgets: chart A, chart B, chart C, chart D" + " " * 40
_PUBLIC = "<html>Pricing tiers: Basic, Pro, Enterprise. Sign up today!</html>" + " " * 40


class _Resp:
    def __init__(self, status: int, text: str) -> None:
        self.status_code = status
        self.text = text


class _App:
    """Routes by path + identity cookie. Anonymous == no Cookie header."""

    def __init__(self, *a: object, **k: object) -> None:
        pass

    async def request(self, method: str, url: str, *, headers: dict | None = None) -> _Resp:
        cookie = (headers or {}).get("Cookie", "")
        path = urlsplit(url).path
        if path == "/account/1":                       # BOLA + sensitive; anon denied
            return _Resp(200, _SENSITIVE) if cookie in ("admin", "user") else _Resp(403, "Forbidden")
        if path == "/dashboard/7":                     # BOLA, non-sensitive; anon denied
            return _Resp(200, _PRIVATE_PLAIN) if cookie in ("admin", "user") else _Resp(302, "")
        if path == "/pricing":                         # public template, everyone incl anon
            return _Resp(200, _PUBLIC)
        if path == "/api/profile":                     # sensitive, reachable anonymously
            return _Resp(200, _SENSITIVE)
        return _Resp(404, "nf")

    async def aclose(self) -> None:
        pass


def _ctx(*paths: str) -> SimpleNamespace:
    eps = [Endpoint(url=f"http://h{p}", method=HttpMethod.GET) for p in paths]
    return SimpleNamespace(
        endpoints=eps,
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(
            identities=[{"name": "admin", "cookie": "admin"}, {"name": "user", "cookie": "user"}],
            timeout=5.0,
        ),
    )


async def test_bola_with_pii_escalates_to_critical(monkeypatch):
    monkeypatch.setattr(am.httpx, "AsyncClient", _App)
    (f,) = [x async for x in AuthorizationMatrixScanner().scan(_ctx("/account/1"))]
    assert f.severity == Severity.CRITICAL and f.cwe == "CWE-639"
    assert f.confidence == Confidence.FIRM
    assert "email" in (f.evidence.notes or "")           # concrete leaked-data evidence
    assert "alice@corp.example" not in (f.evidence.notes or "")  # but redacted


async def test_bola_without_sensitive_body_stays_high(monkeypatch):
    monkeypatch.setattr(am.httpx, "AsyncClient", _App)
    (f,) = [x async for x in AuthorizationMatrixScanner().scan(_ctx("/dashboard/7"))]
    assert f.severity == Severity.HIGH and f.cwe == "CWE-639"


async def test_public_page_is_not_flagged(monkeypatch):
    monkeypatch.setattr(am.httpx, "AsyncClient", _App)
    findings = [x async for x in AuthorizationMatrixScanner().scan(_ctx("/pricing"))]
    assert findings == []                                 # anon control rules out the public page


async def test_anonymous_sensitive_exposure_is_critical_missing_auth(monkeypatch):
    monkeypatch.setattr(am.httpx, "AsyncClient", _App)
    (f,) = [x async for x in AuthorizationMatrixScanner().scan(_ctx("/api/profile"))]
    assert f.severity == Severity.CRITICAL and f.cwe == "CWE-306"
    assert "without authentication" in f.title
    assert describe(scan_sensitive(_SENSITIVE)) in (f.evidence.notes or "") or "email" in (f.evidence.notes or "")
