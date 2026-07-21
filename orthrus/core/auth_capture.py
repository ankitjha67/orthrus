"""Capture an authenticated session from a HAR export.

The painful part of testing a Cloudflare-fronted SPA is harvesting the live session
- ``cf_clearance``, the session cookies, and the exact User-Agent the clearance is
bound to - and getting them into the scanner. But the operator already exports a HAR
of the logged-in app to map its API (``--import-spec``). That same HAR carries the
session in its request headers. This module pulls the auth material out of it, so one
export yields both the API surface and the credentials.

Pure and dependency-free (no browser needed): it reads the HAR JSON, finds requests to
the target host, and builds an ``identities.json`` entry (or an ``--auth-cookie``
string) from the richest ``Cookie`` / ``User-Agent`` / ``Authorization`` it sees.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass(frozen=True)
class AuthMaterial:
    """The session extracted for one host."""

    host: str
    cookie: str = ""
    user_agent: str = ""
    token: str = ""                                     # bearer token, if present
    extra_headers: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return bool(self.cookie or self.token)


def _header(headers: list, name: str) -> str:
    """Case-insensitive lookup over a HAR ``[{name, value}]`` header list."""
    want = name.lower()
    for item in headers or []:
        if isinstance(item, dict) and str(item.get("name", "")).lower() == want:
            return str(item.get("value", ""))
    return ""


def _cookie_from_entry(request: dict) -> str:
    """Prefer the raw Cookie header; fall back to assembling request.cookies."""
    raw = _header(request.get("headers", []), "cookie")
    if raw:
        return raw.strip()
    pairs = [
        f"{c.get('name')}={c.get('value')}"
        for c in request.get("cookies", []) or []
        if isinstance(c, dict) and c.get("name")
    ]
    return "; ".join(pairs)


def _bearer(request: dict) -> str:
    auth = _header(request.get("headers", []), "authorization")
    return auth[7:].strip() if auth[:7].lower() == "bearer " else ""


def auth_from_har(har: str | dict, host: str) -> AuthMaterial | None:
    """Extract the richest session for ``host`` from a HAR document.

    Scans every entry whose request URL matches ``host`` and keeps the one with the
    longest ``Cookie`` header (the most complete session). Also captures the
    User-Agent and a bearer token if the app uses one. Returns ``None`` if the host
    never appears or carries no credentials.
    """
    if isinstance(har, str):
        try:
            har = json.loads(har)
        except (ValueError, TypeError):
            return None
    entries = (((har or {}).get("log") or {}).get("entries")) if isinstance(har, dict) else None
    if not isinstance(entries, list):
        return None

    host = host.lower().lstrip(".")
    best: AuthMaterial | None = None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        request = entry.get("request") or {}
        url = str(request.get("url", ""))
        entry_host = (urlsplit(url).hostname or "").lower()
        if not entry_host or (entry_host != host and not entry_host.endswith("." + host)):
            continue
        cookie = _cookie_from_entry(request)
        token = _bearer(request)
        if not cookie and not token:
            continue
        material = AuthMaterial(
            host=host,
            cookie=cookie,
            user_agent=_header(request.get("headers", []), "user-agent"),
            token=token,
        )
        # Keep the entry with the most session material (longest cookie + a token).
        weight = len(cookie) + (1000 if token else 0)
        best_weight = (len(best.cookie) + (1000 if best.token else 0)) if best else -1
        if weight > best_weight:
            best = material
    return best if (best and best.ok) else None


def to_identity(name: str, material: AuthMaterial) -> dict:
    """Build an ``identities.json`` entry from captured auth material."""
    entry: dict = {"name": name}
    if material.cookie:
        entry["cookie"] = material.cookie
    if material.token:
        entry["token"] = material.token
    headers = dict(material.extra_headers)
    if material.user_agent:
        headers["User-Agent"] = material.user_agent
    if headers:
        entry["headers"] = headers
    return entry


def merge_identity(identities: list, entry: dict) -> list:
    """Return ``identities`` with ``entry`` added, replacing any same-named entry."""
    name = entry.get("name")
    merged = [i for i in identities if not (isinstance(i, dict) and i.get("name") == name)]
    merged.append(entry)
    return merged


__all__ = ["AuthMaterial", "auth_from_har", "to_identity", "merge_identity"]
