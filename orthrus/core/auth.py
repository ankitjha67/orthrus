"""Programmatic pre-scan authentication.

Most real targets only expose their interesting surface behind a login, so
ORTHRUS authenticates once before recon and replays the session for every later
request. This module covers the auth styles modern apps actually use:

* **Form / JSON login** — POST credentials; the response ``Set-Cookie`` jar
  persists automatically and an optional JSON bearer token is attached to later
  requests.
* **Rotating CSRF tokens** — GET the login page first, harvest the anti-CSRF
  token (hidden form field, ``<meta>`` tag, or double-submit cookie) and replay
  it in the login body and/or a request header.
* **MFA (TOTP)** — given a base32 shared secret, compute the RFC 6238 one-time
  code inline (dependency-free) and submit it with the credentials.
* **OAuth2 / OIDC** — acquire a bearer token from a token endpoint via the
  ``password``, ``client_credentials`` or ``refresh_token`` grant.
* **Session refresh** — detect a dropped/expired session mid-scan and silently
  re-authenticate (see :func:`looks_unauthenticated` and the ``Session.reauth``
  hook wired by the orchestrator).

Full SP-initiated SAML / interactive SSO redirect dances and push/SMS MFA can't
be driven head-less; for those, capture a live session and pass ``--auth-cookie``.

Every request still flows through the scope-enforced HttpClient. Credentials and
tokens are never logged — only whether authentication succeeded.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import struct
import time
from collections.abc import Iterable
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

# Field names commonly used for anti-CSRF tokens in HTML forms / meta tags.
COMMON_CSRF_FIELDS = (
    "csrf_token",
    "csrfmiddlewaretoken",
    "authenticity_token",
    "__RequestVerificationToken",
    "_csrf",
    "_token",
    "csrf",
    "xsrf",
)
# Cookie names used by the "double-submit" pattern (token mirrored in a cookie).
COMMON_CSRF_COOKIES = ("XSRF-TOKEN", "csrftoken", "CSRF-TOKEN", "_csrf")
# Response substrings / statuses that usually mean "you are no longer logged in".
DEFAULT_REAUTH_MARKERS = ("please log in", "session expired", "login required", "unauthorized")


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


# --------------------------------------------------------------------- TOTP
def _normalize_base32(secret: str) -> str:
    cleaned = re.sub(r"\s+", "", secret or "").upper()
    return cleaned + "=" * ((-len(cleaned)) % 8)


def compute_totp(
    secret: str,
    *,
    at: float | None = None,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
) -> str:
    """RFC 6238 time-based one-time password from a base32 ``secret``.

    Dependency-free (no pyotp) so MFA works out of the box; verified against the
    RFC 6238 published test vectors. ``at`` overrides the current Unix time for
    deterministic testing.
    """
    key = base64.b32decode(_normalize_base32(secret), casefold=True)
    counter = int((time.time() if at is None else at) // period)
    msg = struct.pack(">Q", counter)
    digestmod = getattr(hashlib, algorithm.lower().replace("-", ""))
    digest = hmac.new(key, msg, digestmod).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10**digits)).zfill(digits)


# ---------------------------------------------------------------- CSRF tokens
_TAG_RE = re.compile(r"<(?:input|meta)\b[^>]*>", re.IGNORECASE)
_ATTR_RE = re.compile(
    r"""([a-zA-Z_:][\w:.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""",
)


def _tag_attrs(tag: str) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for match in _ATTR_RE.finditer(tag):
        name = match.group(1).lower()
        value = match.group(2) or match.group(3) or match.group(4) or ""
        attrs[name] = value
    return attrs


def parse_csrf_token(html: str, field_names: Iterable[str]) -> str | None:
    """Extract a CSRF token from HTML by ``<input>``/``<meta>`` name or id."""
    wanted = {n.lower() for n in field_names}
    for tag in _TAG_RE.findall(html or ""):
        attrs = _tag_attrs(tag)
        ident = (attrs.get("name") or attrs.get("id") or "").lower()
        if ident in wanted:
            token = attrs.get("value") or attrs.get("content")
            if token:
                return token
    return None


def csrf_token_from_cookies(cookies: dict[str, str], names: Iterable[str]) -> str | None:
    """Find a CSRF token mirrored in a cookie (double-submit pattern)."""
    lowered = {k.lower(): v for k, v in (cookies or {}).items()}
    for name in names:
        value = lowered.get(name.lower())
        if value:
            return value
    return None


def harvest_csrf(html: str, cookies: dict[str, str], *, field: str | None = None) -> str | None:
    """Pull a CSRF token from a login page: form/meta first, then a cookie."""
    html_names = [field] if field else list(COMMON_CSRF_FIELDS)
    token = parse_csrf_token(html, html_names)
    if token:
        return token
    cookie_names = ([field] if field else []) + list(COMMON_CSRF_COOKIES)
    return csrf_token_from_cookies(cookies, cookie_names)


def _response_cookies(resp: Any) -> dict[str, str]:
    try:
        return {k: v for k, v in dict(resp.cookies).items()}
    except (AttributeError, TypeError, ValueError):
        return {}


# --------------------------------------------------------------- form / JSON
async def perform_login(
    http: HttpClient,
    session: Session,
    *,
    login_url: str,
    login_data: str,
    token_field: str | None = None,
    success_marker: str | None = None,
    csrf_url: str | None = None,
    csrf_field: str | None = None,
    csrf_header: str | None = None,
    totp_secret: str | None = None,
    totp_field: str = "otp",
) -> LoginResult:
    """POST credentials (with optional CSRF + TOTP) and capture the session.

    When ``csrf_field``/``csrf_header`` is set, the page at ``csrf_url`` (default:
    ``login_url``) is fetched first to harvest a rotating anti-CSRF token, which
    is then replayed in the login body and/or a request header. When
    ``totp_secret`` is set, a fresh RFC 6238 code is added under ``totp_field``.

    Success is determined by (in priority order): a token extracted when
    ``token_field`` is set, the presence of ``success_marker`` in the response,
    or a non-error status code.
    """
    payload, is_json = parse_login_data(login_data)
    headers: dict[str, str] = {}

    if csrf_field or csrf_header:
        try:
            page = await http.get(csrf_url or login_url)
            token = harvest_csrf(page.text, _response_cookies(page), field=csrf_field)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            return LoginResult(ok=False, reason=f"csrf-prefetch:{type(exc).__name__}")
        if token:
            if csrf_field and isinstance(payload, dict):
                payload[csrf_field] = token
            if csrf_header:
                headers[csrf_header] = token

    if totp_secret and isinstance(payload, dict):
        payload[totp_field] = compute_totp(totp_secret)

    try:
        if is_json:
            resp = await http.post(login_url, json=payload, headers=headers or None)
        else:
            resp = await http.post(login_url, data=payload, headers=headers or None)
    except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
        return LoginResult(ok=False, reason=type(exc).__name__)

    token_set = False
    if token_field:
        try:
            extracted = extract_token(resp.json(), token_field)
        except (ValueError, json.JSONDecodeError):
            extracted = None
        if extracted:
            session.bearer_token = extracted
            token_set = True

    if token_field:
        ok = token_set
    elif success_marker:
        ok = success_marker in resp.text
    else:
        ok = resp.status_code < 400

    return LoginResult(ok=ok, status=resp.status_code, token_set=token_set)


# ------------------------------------------------------------------- OAuth2
def build_oauth2_request(
    grant_type: str,
    *,
    client_id: str | None = None,
    client_secret: str | None = None,
    username: str | None = None,
    password: str | None = None,
    scope: str | None = None,
    refresh_token: str | None = None,
) -> dict[str, str]:
    """Build the form body for an OAuth2 token request (RFC 6749).

    Supports the ``password``, ``client_credentials`` and ``refresh_token``
    grants. Client credentials are sent in the body when provided (callers may
    instead use HTTP Basic via a header).
    """
    data: dict[str, str] = {"grant_type": grant_type}
    if grant_type == "password":
        if username is not None:
            data["username"] = username
        if password is not None:
            data["password"] = password
    elif grant_type == "refresh_token":
        if refresh_token is not None:
            data["refresh_token"] = refresh_token
    elif grant_type != "client_credentials":
        raise ValueError(f"unsupported OAuth2 grant_type: {grant_type!r}")
    if scope:
        data["scope"] = scope
    if client_id:
        data["client_id"] = client_id
    if client_secret:
        data["client_secret"] = client_secret
    return data


async def acquire_oauth2_token(
    http: HttpClient,
    session: Session,
    *,
    token_url: str,
    grant_type: str = "password",
    client_id: str | None = None,
    client_secret: str | None = None,
    username: str | None = None,
    password: str | None = None,
    scope: str | None = None,
    refresh_token: str | None = None,
    token_field: str = "access_token",
) -> LoginResult:
    """Fetch an OAuth2 bearer token and attach it to the session."""
    try:
        data = build_oauth2_request(
            grant_type,
            client_id=client_id,
            client_secret=client_secret,
            username=username,
            password=password,
            scope=scope,
            refresh_token=refresh_token,
        )
    except ValueError as exc:
        return LoginResult(ok=False, reason=str(exc))

    try:
        resp = await http.post(token_url, data=data, headers={"Accept": "application/json"})
    except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
        return LoginResult(ok=False, reason=type(exc).__name__)

    try:
        token = extract_token(resp.json(), token_field)
    except (ValueError, json.JSONDecodeError):
        token = None
    if token:
        session.bearer_token = token
    return LoginResult(ok=bool(token), status=resp.status_code, token_set=bool(token))


# ------------------------------------------------------------- session refresh
def looks_unauthenticated(
    status: int,
    body: str,
    markers: Iterable[str] = DEFAULT_REAUTH_MARKERS,
) -> bool:
    """Heuristic: does this response indicate the session has been dropped?

    True on a 401, or when a body marker (case-insensitive) is present. Kept
    conservative so we don't needlessly re-authenticate on legitimate 403s.
    """
    if status == 401:
        return True
    haystack = (body or "").lower()
    return any(marker.lower() in haystack for marker in markers)


__all__ = [
    "COMMON_CSRF_COOKIES",
    "COMMON_CSRF_FIELDS",
    "DEFAULT_REAUTH_MARKERS",
    "LoginResult",
    "acquire_oauth2_token",
    "build_oauth2_request",
    "compute_totp",
    "csrf_token_from_cookies",
    "extract_token",
    "harvest_csrf",
    "looks_unauthenticated",
    "parse_csrf_token",
    "parse_login_data",
    "perform_login",
]
