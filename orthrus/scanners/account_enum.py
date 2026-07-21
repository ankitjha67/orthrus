"""Account / user enumeration scanner.

Login, registration, and password-reset endpoints often reveal whether an account
exists - "no account with that email", "user not found", "email already registered" -
which lets an attacker build a valid-user list for targeted phishing, stuffing, or
reset abuse. This probes those endpoints with a random, almost-certainly-nonexistent
identifier and flags a response that explicitly reveals (non-)existence instead of a
generic "invalid credentials" / "if an account exists we sent a link".

Single probe per endpoint, invalid identifier only - non-destructive and non-bursting.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import (
    Aggressiveness,
    Confidence,
    Evidence,
    Finding,
    HttpMethod,
    ParamLocation,
    Severity,
)
from orthrus.scanners._authflow import classify_action
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.default_creds import USER_FIELDS
from orthrus.scanners.registry import register
from orthrus.utils.scope import ScopeViolation

SCANNER_NAME = "account-enumeration"
MAX_ENDPOINTS = 8
_ENUM_ACTIONS = frozenset({"login", "register", "password-reset"})

# Phrases that explicitly reveal whether an account exists (an enumeration oracle).
REVEAL_MARKERS = (
    "not found", "no account", "does not exist", "doesn't exist", "no user",
    "user not found", "email not found", "not registered", "unregistered",
    "unknown user", "no such user", "invalid username", "invalid email",
    "already registered", "already exists", "already taken", "already in use",
    "email is taken", "username is taken", "account exists",
)
# Generic, safe phrasings that must NOT be treated as an oracle.
SAFE_MARKERS = (
    "invalid credentials", "incorrect password", "invalid username or password",
    "if an account", "if this email", "if that email", "check your email",
)


def reveals_existence(body: str) -> str | None:
    """Return the existence-revealing phrase found in ``body``, or None.

    A generic 'invalid credentials' / 'if an account exists' response is safe and
    suppresses the signal even if a reveal phrase also appears.
    """
    low = (body or "").lower()
    if any(safe in low for safe in SAFE_MARKERS):
        return None
    return next((marker for marker in REVEAL_MARKERS if marker in low), None)


@register
class AccountEnumScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "account-enumeration"
    min_aggressiveness = Aggressiveness.NORMAL  # single probes, no burst

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        tested = 0
        seen: set[str] = set()
        for ep in ctx.endpoints:
            if tested >= MAX_ENDPOINTS:
                break
            if ep.method not in (HttpMethod.POST, HttpMethod.PUT):
                continue
            body_params = [p for p in ep.params if p.location in (ParamLocation.BODY, ParamLocation.JSON)]
            action = classify_action(ep.url, [p.name for p in body_params])
            if action not in _ENUM_ACTIONS:
                continue
            key = urlsplit(ep.url).path
            if key in seen or not ctx.scope.is_allowed(ep.url):
                continue
            seen.add(key)
            tested += 1

            resp = await self._probe(ctx, ep, body_params)
            if resp is None:
                continue
            marker = reveals_existence(resp.text)
            if marker is not None:
                yield self._finding(ep, action, marker)

    async def _probe(
        self, ctx: ScanContext, ep: object, body_params: list
    ) -> httpx.Response | None:
        nonce = secrets.token_hex(6)
        ident = f"orthrus-{nonce}@example.com"
        is_json = any(p.location == ParamLocation.JSON for p in body_params)
        body = {
            p.name: (ident if p.name.lower() in USER_FIELDS else (p.value or "orthrus"))
            for p in body_params
        } or {"email": ident}
        try:
            kwargs: dict = {"follow_redirects": False}
            if is_json:
                kwargs["json"] = body
            else:
                kwargs["data"] = body
            return await ctx.http.request(ep.method.value, ep.url, **kwargs)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL):
            return None

    def _finding(self, ep: object, action: str, marker: str) -> Finding:
        label = action.replace("-", " ")
        return Finding(
            vuln_type="account-enumeration",
            title=f"Account enumeration via {label} response at {urlsplit(ep.url).path}",
            severity=Severity.MEDIUM,
            confidence=Confidence.FIRM,
            url=ep.url,
            description=(
                f"The {label} endpoint responded to a random, non-existent identifier with a "
                f"message that reveals account (non-)existence ('{marker}'). An attacker can "
                "distinguish valid from invalid accounts to build a target list for phishing, "
                "credential stuffing, or password-reset abuse."
            ),
            remediation=(
                "Return a uniform response regardless of whether the account exists: a generic "
                "'invalid credentials' on login, and 'if an account exists we've sent an email' on "
                "reset/registration. Keep status codes and timing uniform too."
            ),
            cwe="CWE-204",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                request_raw=f"random identifier -> {ep.method.value} {urlsplit(ep.url).path}",
                matched_at=marker,
                notes=f"response revealed existence with: '{marker}'",
            ),
        )


__all__ = ["AccountEnumScanner", "reveals_existence", "SCANNER_NAME"]
