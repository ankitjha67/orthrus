"""Session / authentication state shared across requests.

Holds cookies, default headers, and bearer tokens for an engagement so that
authenticated crawling and scanning replay the operator-provided session.
Automated login (Playwright ``--auth-script``) is deferred; the hooks here cover
cookie- and token-based pre-authentication today.
"""

from __future__ import annotations

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
