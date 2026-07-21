"""Multi-identity model for authorization testing (Autorize-style BOLA/BFLA).

An *identity* is a distinct authenticated (or anonymous) principal - e.g.
``admin``, ``user``, ``anonymous`` - supplied by the operator so ORTHRUS can
replay the same request as each principal and compare what they are allowed to
see. The first identity in the list is treated as the privileged **baseline**;
the rest are tested against it.

Identities are intentionally simple credential bundles (a Cookie string, a
bearer token, and/or extra headers) so they isolate cleanly: each is replayed
through its own client with no shared cookie jar, so one identity's session can
never leak into another's request.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Identity:
    """A single principal used for authorization comparison."""

    name: str
    cookie: str | None = None
    token: str | None = None
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def is_authenticated(self) -> bool:
        """True if the identity carries any auth material (vs. anonymous)."""
        return bool(self.cookie or self.token or self.headers)


def parse_identities(raw: object) -> list[Identity]:
    """Parse identities from a list of dicts or a JSON string.

    Each entry: ``{"name": "...", "cookie": "...", "token": "...",
    "headers": {...}}`` - all fields except a usable label are optional. An
    entry with no cookie/token/headers is an anonymous identity. Malformed input
    yields an empty list (the scanner then no-ops).
    """
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (ValueError, TypeError):
            return []
    if not isinstance(raw, list):
        return []
    identities: list[Identity] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or f"identity{len(identities) + 1}")
        cookie = item.get("cookie")
        token = item.get("token") or item.get("bearer")
        headers = item.get("headers")
        identities.append(
            Identity(
                name=name,
                cookie=cookie if isinstance(cookie, str) else None,
                token=token if isinstance(token, str) else None,
                headers={str(k): str(v) for k, v in headers.items()}
                if isinstance(headers, dict)
                else {},
            )
        )
    return identities


def identity_headers(identity: Identity) -> dict[str, str]:
    """Build the request headers that carry this identity's auth.

    A raw ``Cookie`` header is safe here because each identity is replayed
    through a client with no cookie jar, so nothing else contributes cookies.
    """
    headers = dict(identity.headers)
    if identity.cookie:
        headers["Cookie"] = identity.cookie
    if identity.token:
        headers.setdefault("Authorization", f"Bearer {identity.token}")
    return headers


__all__ = ["Identity", "parse_identities", "identity_headers"]
