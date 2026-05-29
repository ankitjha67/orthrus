"""Modern auth-flow engine: TOTP MFA, rotating CSRF, OAuth2, session refresh.

Pure-logic + duck-typed fakes (no live server) so the whole auth surface is
deterministically covered. TOTP is checked against the published RFC 6238 test
vectors; the HTTP client's silent re-auth retry is exercised with a bare client
whose ``_send`` is stubbed.
"""

from __future__ import annotations

import pytest

from orthrus.core.auth import (
    DEFAULT_REAUTH_MARKERS,
    acquire_oauth2_token,
    build_oauth2_request,
    compute_totp,
    harvest_csrf,
    looks_unauthenticated,
    parse_csrf_token,
    perform_login,
)
from orthrus.core.http_client import HttpClient
from orthrus.core.session import Session


# --------------------------------------------------------------- duck-typed fakes
class FakeResp:
    def __init__(
        self,
        status: int = 200,
        *,
        text: str = "",
        payload: dict | None = None,
        cookies: dict | None = None,
    ) -> None:
        self.status_code = status
        self.text = text
        self._payload = payload
        self.cookies = cookies or {}

    def json(self) -> dict:
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class FakeHttp:
    """Records GET/POST calls and returns canned responses."""

    def __init__(self, get_resp: FakeResp | None = None, post_resp: FakeResp | None = None) -> None:
        self.get_resp = get_resp
        self.post_resp = post_resp
        self.get_calls: list[tuple[str, dict]] = []
        self.post_calls: list[tuple[str, dict]] = []

    async def get(self, url: str, **kwargs: object) -> FakeResp:
        self.get_calls.append((url, kwargs))
        assert self.get_resp is not None
        return self.get_resp

    async def post(self, url: str, **kwargs: object) -> FakeResp:
        self.post_calls.append((url, kwargs))
        assert self.post_resp is not None
        return self.post_resp


# ----------------------------------------------------------------------- TOTP
# RFC 6238 Appendix B test vectors (SHA-1, 8 digits, secret = ASCII
# "12345678901234567890" -> base32 below).
_RFC6238_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


@pytest.mark.parametrize(
    ("at", "expected"),
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ],
)
def test_compute_totp_matches_rfc6238_vectors(at: int, expected: str) -> None:
    assert compute_totp(_RFC6238_SECRET, at=at, digits=8) == expected


def test_compute_totp_six_digits_default_length() -> None:
    code = compute_totp(_RFC6238_SECRET, at=59)
    assert len(code) == 6 and code.isdigit()


def test_compute_totp_tolerates_spaces_and_lowercase() -> None:
    spaced = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq"
    assert compute_totp(spaced, at=59, digits=8) == "94287082"


# ----------------------------------------------------------------------- CSRF
def test_parse_csrf_token_from_input_and_meta() -> None:
    assert parse_csrf_token('<input name="csrf_token" value="ABC" type="hidden">', ["csrf_token"]) == "ABC"
    assert parse_csrf_token('<meta name="csrf-token" content="MET">', ["csrf-token"]) == "MET"
    assert parse_csrf_token('<input id="_token" value="BYID">', ["_token"]) == "BYID"
    assert parse_csrf_token("<p>nothing</p>", ["csrf_token"]) is None


def test_harvest_csrf_prefers_html_then_cookie() -> None:
    assert harvest_csrf('<input id="authenticity_token" value="HTOK">', {}) == "HTOK"
    # No HTML token -> fall back to a double-submit cookie.
    assert harvest_csrf("<html></html>", {"csrftoken": "CK"}) == "CK"
    assert harvest_csrf("<html></html>", {}) is None


# ----------------------------------------------------------------- perform_login
async def test_perform_login_harvests_and_injects_csrf_and_totp() -> None:
    page = FakeResp(text='<input type="hidden" name="csrf_token" value="TOK123">')
    http = FakeHttp(get_resp=page, post_resp=FakeResp(200, text="Welcome"))
    session = Session()
    result = await perform_login(
        http,  # type: ignore[arg-type]
        session,
        login_url="http://h/login",
        login_data="user=admin&password=admin",
        csrf_field="csrf_token",
        csrf_header="X-CSRF-Token",
        totp_secret=_RFC6238_SECRET,
    )
    assert result.ok is True
    # The CSRF token was fetched from the login page by default.
    assert http.get_calls[0][0] == "http://h/login"
    _, kwargs = http.post_calls[0]
    body = kwargs["data"]
    assert body["csrf_token"] == "TOK123"
    assert kwargs["headers"]["X-CSRF-Token"] == "TOK123"
    assert body["otp"].isdigit() and len(body["otp"]) == 6


async def test_perform_login_csrf_from_cookie_into_header_only() -> None:
    page = FakeResp(text="<html>no field</html>", cookies={"XSRF-TOKEN": "CK99"})
    http = FakeHttp(get_resp=page, post_resp=FakeResp(200, text="ok"))
    session = Session()
    await perform_login(
        http,  # type: ignore[arg-type]
        session,
        login_url="http://h/login",
        csrf_url="http://h/",
        login_data="u=a&p=b",
        csrf_header="X-XSRF-TOKEN",
    )
    assert http.get_calls[0][0] == "http://h/"  # explicit csrf_url honoured
    _, kwargs = http.post_calls[0]
    assert kwargs["headers"]["X-XSRF-TOKEN"] == "CK99"
    assert "csrf_token" not in kwargs["data"]  # no csrf_field -> body untouched


# ----------------------------------------------------------------------- OAuth2
def test_build_oauth2_request_per_grant() -> None:
    assert build_oauth2_request("password", username="u", password="p", scope="read") == {
        "grant_type": "password",
        "username": "u",
        "password": "p",
        "scope": "read",
    }
    assert build_oauth2_request("client_credentials", client_id="id", client_secret="s") == {
        "grant_type": "client_credentials",
        "client_id": "id",
        "client_secret": "s",
    }
    assert build_oauth2_request("refresh_token", refresh_token="r") == {
        "grant_type": "refresh_token",
        "refresh_token": "r",
    }


def test_build_oauth2_request_rejects_unknown_grant() -> None:
    with pytest.raises(ValueError):
        build_oauth2_request("implicit")


async def test_acquire_oauth2_token_sets_bearer() -> None:
    http = FakeHttp(post_resp=FakeResp(200, payload={"access_token": "AT-1", "token_type": "Bearer"}))
    session = Session()
    result = await acquire_oauth2_token(
        http,  # type: ignore[arg-type]
        session,
        token_url="http://h/oauth/token",
        grant_type="password",
        username="u",
        password="p",
        client_id="c",
    )
    assert result.ok is True and result.token_set is True
    assert session.bearer_token == "AT-1"
    assert session.default_headers()["Authorization"] == "Bearer AT-1"
    _, kwargs = http.post_calls[0]
    assert kwargs["data"]["grant_type"] == "password"
    assert kwargs["data"]["username"] == "u"


async def test_acquire_oauth2_token_missing_token_is_failure() -> None:
    http = FakeHttp(post_resp=FakeResp(400, payload={"error": "invalid_grant"}))
    session = Session()
    result = await acquire_oauth2_token(
        http,  # type: ignore[arg-type]
        session,
        token_url="http://h/oauth/token",
        grant_type="client_credentials",
        client_id="c",
        client_secret="s",
    )
    assert result.ok is False and session.bearer_token is None


# ------------------------------------------------------------- session refresh
def test_looks_unauthenticated_heuristics() -> None:
    assert looks_unauthenticated(401, "") is True
    assert looks_unauthenticated(200, "Please log in to continue") is True
    assert looks_unauthenticated(200, "Welcome to your dashboard") is False
    # Conservative: a plain 403 is not treated as a dropped session.
    assert looks_unauthenticated(403, "forbidden") is False
    assert looks_unauthenticated(200, "boom", markers=("boom",)) is True


async def test_http_client_reauths_once_then_retries() -> None:
    # Bare client: request() only touches _send, session, _reauthing, reauth_markers.
    client = HttpClient.__new__(HttpClient)
    client.session = Session()
    client._reauthing = False
    client.reauth_markers = DEFAULT_REAUTH_MARKERS
    responses = [FakeResp(401, text="unauthorized"), FakeResp(200, text="ok")]
    sent: list[tuple[str, str]] = []

    async def fake_send(method: str, url: str, **kwargs: object) -> FakeResp:
        sent.append((method, url))
        return responses[len(sent) - 1]

    client._send = fake_send  # type: ignore[method-assign,assignment]

    reauth_calls = {"n": 0}

    async def reauth() -> bool:
        reauth_calls["n"] += 1
        return True

    client.session.reauth = reauth
    resp = await client.request("GET", "http://h/protected")
    assert resp.status_code == 200
    assert reauth_calls["n"] == 1
    assert len(sent) == 2  # original + one retry


async def test_http_client_no_reauth_when_hook_absent() -> None:
    client = HttpClient.__new__(HttpClient)
    client.session = Session()  # no reauth hook installed
    client._reauthing = False
    client.reauth_markers = DEFAULT_REAUTH_MARKERS
    sent: list[str] = []

    async def fake_send(method: str, url: str, **kwargs: object) -> FakeResp:
        sent.append(url)
        return FakeResp(401, text="unauthorized")

    client._send = fake_send  # type: ignore[method-assign,assignment]
    resp = await client.request("GET", "http://h/protected")
    assert resp.status_code == 401
    assert len(sent) == 1  # no retry without a reauth hook


async def test_http_client_no_retry_when_reauth_fails() -> None:
    client = HttpClient.__new__(HttpClient)
    client.session = Session()
    client._reauthing = False
    client.reauth_markers = DEFAULT_REAUTH_MARKERS
    sent: list[str] = []

    async def fake_send(method: str, url: str, **kwargs: object) -> FakeResp:
        sent.append(url)
        return FakeResp(401, text="unauthorized")

    client._send = fake_send  # type: ignore[method-assign,assignment]

    async def reauth() -> bool:
        return False

    client.session.reauth = reauth
    resp = await client.request("GET", "http://h/protected")
    assert resp.status_code == 401
    assert len(sent) == 1  # reauth failed -> no replay
