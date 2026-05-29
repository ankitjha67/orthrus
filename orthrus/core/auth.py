"""Programmatic pre-scan authentication (form / JSON login).

Most real targets only expose their interesting surface behind a login. Given
credentials, ORTHRUS authenticates once before recon so every later request
replays the session:

* response ``Set-Cookie`` headers persist automatically in the shared HTTP
  client's cookie jar, and
* an optional bearer token pulled from a JSON login response (common for SPAs /
  REST APIs) is attached to all subsequent requests via the Session.

Every request still flows through the scope-enforced HttpClient. Credentials and
tokens are never logged — only whether authentication succeeded.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl

import httpx

from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

if TYPE_CHECKING:
    from orthrus.core.http_client import HttpClient
    from orthrus.core.session import Session

logger = get_logger("auth")


@dataclass
class LoginResult:
    ok: bool
    status: int | None = None
    token_set: bool = False
    reason: str = ""


def parse_login_data(raw: str) -> tuple[Any, bool]:
    """Return (payload, is_json).

    A body that parses as a JSON object is sent as JSON; otherwise it's treated
    as ``key=value&...`` form data.
    """
    text = (raw or "").strip()
    if text[:1] == "{":
        try:
            obj = json.loads(text)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            return obj, True
    return dict(parse_qsl(text, keep_blank_values=True)), False


def extract_token(data: Any, dotted_path: str) -> str | None:
    """Walk a dotted path (``authentication.token``) into a parsed JSON body."""
    current = data
    for part in dotted_path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    if isinstance(current, str):
        return current
    if isinstance(current, (int, float)) and not isinstance(current, bool):
        return str(current)
    return None


async def perform_login(
    http: HttpClient,
    session: Session,
    *,
    login_url: str,
    login_data: str,
    token_field: str | None = None,
    success_marker: str | None = None,
) -> LoginResult:
    """POST credentials and capture the resulting authenticated state.

    Success is determined by (in priority order): a token extracted when
    ``token_field`` is set, the presence of ``success_marker`` in the response,
    or a non-error status code.
    """
    payload, is_json = parse_login_data(login_data)
    try:
        if is_json:
            resp = await http.post(login_url, json=payload)
        else:
            resp = await http.post(login_url, data=payload)
    except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
        return LoginResult(ok=False, reason=type(exc).__name__)

    token_set = False
    if token_field:
        try:
            token = extract_token(resp.json(), token_field)
        except (ValueError, json.JSONDecodeError):
            token = None
        if token:
            session.bearer_token = token
            token_set = True

    if token_field:
        ok = token_set
    elif success_marker:
        ok = success_marker in resp.text
    else:
        ok = resp.status_code < 400

    return LoginResult(ok=ok, status=resp.status_code, token_set=token_set)


__all__ = ["LoginResult", "parse_login_data", "extract_token", "perform_login"]
