"""Programmatic pre-scan login (form / JSON credentials + token extraction)."""

from __future__ import annotations

from orthrus.core.auth import extract_token, parse_login_data, perform_login
from orthrus.core.session import Session


class FakeResp:
    def __init__(self, status: int, *, text: str = "", payload: dict | None = None) -> None:
        self.status_code = status
        self.text = text
        self._payload = payload

    def json(self) -> dict:
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class FakeHttp:
    def __init__(self, resp: FakeResp) -> None:
        self.resp = resp
        self.calls: list[tuple[str, dict]] = []

    async def post(self, url: str, **kwargs: object) -> FakeResp:
        self.calls.append((url, kwargs))
        return self.resp


# ------------------------------------------------------------- pure parsing
def test_parse_login_data_form():
    payload, is_json = parse_login_data("user=admin&password=admin")
    assert is_json is False
    assert payload == {"user": "admin", "password": "admin"}


def test_parse_login_data_json():
    payload, is_json = parse_login_data('{"email":"a@b.c","password":"pw"}')
    assert is_json is True
    assert payload == {"email": "a@b.c", "password": "pw"}


def test_parse_login_data_malformed_json_falls_back_to_form():
    payload, is_json = parse_login_data("{not json")
    assert is_json is False


def test_extract_token_dotted_path():
    data = {"authentication": {"token": "JWT123", "umail": "x"}}
    assert extract_token(data, "authentication.token") == "JWT123"
    assert extract_token(data, "authentication.missing") is None
    assert extract_token(data, "nope") is None


def test_extract_token_numeric_stringified():
    assert extract_token({"id": 42}, "id") == "42"


# -------------------------------------------------------------- perform_login
async def test_form_login_sends_data_and_succeeds_on_status():
    http = FakeHttp(FakeResp(200, text="Welcome admin"))
    session = Session()
    result = await perform_login(
        http, session, login_url="http://h/login", login_data="user=admin&password=admin"
    )
    assert result.ok is True
    assert result.status == 200
    url, kwargs = http.calls[0]
    assert url == "http://h/login"
    assert kwargs["data"] == {"user": "admin", "password": "admin"}


async def test_login_success_marker_required():
    http = FakeHttp(FakeResp(200, text="Invalid credentials"))
    session = Session()
    result = await perform_login(
        http,
        session,
        login_url="http://h/login",
        login_data="user=x&password=y",
        success_marker="Logout",
    )
    assert result.ok is False  # marker absent -> not authenticated


async def test_json_login_extracts_bearer_token():
    http = FakeHttp(FakeResp(200, payload={"authentication": {"token": "JWT-XYZ"}}))
    session = Session()
    result = await perform_login(
        http,
        session,
        login_url="http://h/rest/user/login",
        login_data='{"email":"a@b.c","password":"pw"}',
        token_field="authentication.token",
    )
    assert result.ok is True
    assert result.token_set is True
    assert session.bearer_token == "JWT-XYZ"
    # token now flows into every request's Authorization header
    assert session.default_headers()["Authorization"] == "Bearer JWT-XYZ"
    _, kwargs = http.calls[0]
    assert kwargs["json"] == {"email": "a@b.c", "password": "pw"}


async def test_json_login_missing_token_is_failure():
    http = FakeHttp(FakeResp(200, payload={"authentication": {}}))
    session = Session()
    result = await perform_login(
        http,
        session,
        login_url="http://h/login",
        login_data="{}",
        token_field="authentication.token",
    )
    assert result.ok is False
    assert result.token_set is False
    assert session.bearer_token is None
