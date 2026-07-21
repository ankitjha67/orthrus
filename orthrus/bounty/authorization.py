"""Authorization of a bug-bounty engagement (PRD §2.3 / §6 / §7.1).

Every engagement must be tied to a *source of authorization*: a public program
URL (HackerOne / Bugcrowd / Intigriti / YesWeHack / Immunefi), a signed private
engagement letter, direct written permission, or a self-owned lab. ORTHRUS
refuses to scan public hosts without one - ``--scope auto`` convenience is only
implied when the whole scope is a local lab (loopback / RFC1918).

This module does not verify the *content* of the authorization (that a program
actually lists your target) - it records the operator's attested source so the
audit trail is honest and casual "point it at anything" use is blocked.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit


class AuthKind(StrEnum):
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    YESWEHACK = "yeswehack"
    IMMUNEFI = "immunefi"
    SIGNED = "signed"          # signed:<file-or-hash> - a private engagement letter
    DIRECT = "direct"          # direct:<note> or a policy URL - direct written permission
    SELF_LAB = "self-owned-lab"


_PLATFORM_HOSTS = {
    "hackerone.com": AuthKind.HACKERONE,
    "bugcrowd.com": AuthKind.BUGCROWD,
    "intigriti.com": AuthKind.INTIGRITI,
    "yeswehack.com": AuthKind.YESWEHACK,
    "immunefi.com": AuthKind.IMMUNEFI,
}


class AuthorizationError(ValueError):
    """Raised when an authorization source is missing or unrecognized."""


@dataclass(frozen=True)
class Authorization:
    kind: AuthKind
    reference: str  # the URL / file / hash / note the operator attested


def classify_authorization(source: str) -> Authorization:
    """Parse an ``--authorization`` value into a typed :class:`Authorization`."""
    s = (source or "").strip()
    if not s:
        raise AuthorizationError("empty authorization source")
    low = s.lower()
    if low in ("self", "self-lab", "self-owned", "self-owned-lab", "lab"):
        return Authorization(AuthKind.SELF_LAB, "self-owned-lab")
    if low.startswith("signed:"):
        return Authorization(AuthKind.SIGNED, s.split(":", 1)[1].strip() or s)
    if low.startswith("direct:"):
        return Authorization(AuthKind.DIRECT, s.split(":", 1)[1].strip() or s)
    if "://" in s or "." in s:
        host = (urlsplit(s if "://" in s else "//" + s).hostname or "").lower()
        for phost, kind in _PLATFORM_HOSTS.items():
            if host == phost or host.endswith("." + phost):
                return Authorization(kind, s)
        if "://" in s:  # a link to the program's own policy page = direct permission
            return Authorization(AuthKind.DIRECT, s)
    raise AuthorizationError(
        f"unrecognized authorization source {source!r}. Use a program URL "
        "(e.g. https://hackerone.com/acme), 'signed:<file-or-hash>', "
        "'direct:<note>', or 'self-owned-lab'."
    )


def _is_private_host(host: str) -> bool:
    h = (host or "").lower().rstrip(".")
    if h == "localhost" or h.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def scope_is_private_lab(hosts: list[str]) -> bool:
    """True iff every host is loopback / RFC1918 / ``localhost`` (a local lab)."""
    real = [h for h in hosts if h]
    return bool(real) and all(_is_private_host(h) for h in real)


def resolve_authorization(source: str | None, in_scope_hosts: list[str]) -> Authorization:
    """Resolve the engagement authorization, or raise.

    An explicit ``source`` always wins. With none, a wholly-private scope is
    treated as a self-owned lab; anything with a public host is refused.
    """
    if source:
        return classify_authorization(source)
    if scope_is_private_lab(in_scope_hosts):
        return Authorization(AuthKind.SELF_LAB, "self-owned-lab (all in-scope hosts are local/private)")
    raise AuthorizationError(
        "this scope includes public hosts, so an authorization source is required. "
        "Pass --authorization with the program URL (e.g. https://hackerone.com/acme), "
        "'signed:<file>', 'direct:<note>', or 'self-owned-lab' for a lab you own."
    )


__all__ = [
    "AuthKind",
    "Authorization",
    "AuthorizationError",
    "classify_authorization",
    "resolve_authorization",
    "scope_is_private_lab",
]
