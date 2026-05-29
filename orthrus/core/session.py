"""Session / authentication state shared across requests.

Holds cookies, default headers, and bearer tokens for an engagement so that
authenticated crawling and scanning replay the operator-provided session.
Cookie-, token-, form-, OAuth2- and CSRF/MFA-based pre-authentication is handled
by :mod:`orthrus.core.auth`; this object carries the resulting state plus an
optional ``reauth`` hook the HTTP client calls to silently re-establish a
session that expired mid-scan.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from http.cookies import SimpleCookie


class Session:
    def __init__(
        self,
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        bearer_token: str | None = None,
    ) -> None:
        self.cookies: dict[str, str] = cookies or {}
        self.headers: dict[str, str] = headers or {}
        self.bearer_token = bearer_token
        # Set by the orchestrator when --reauth is enabled: an idempotent
        # coroutine that re-runs the login flow and returns True on success.
        # The HTTP client invokes it (once per request) when a response looks
        # unauthenticated, then retries the original request.
        self.reauth: Callable[[], Awaitable[bool]] | None = None

    @classmethod
    def from_cookie_string(cls, raw: str | None) -> Session:
        """Parse a ``--auth-cookie`` string like ``sid=abc; theme=dark``."""
        session = cls()
        if not raw:
            return session
        jar: SimpleCookie = SimpleCookie()
        jar.load(raw)
        session.cookies = {key: morsel.value for key, morsel in jar.items()}
        return session

    def default_headers(self) -> dict[str, str]:
        headers = dict(self.headers)
        if self.bearer_token:
            headers.setdefault("Authorization", f"Bearer {self.bearer_token}")
        return headers


__all__ = ["Session"]
