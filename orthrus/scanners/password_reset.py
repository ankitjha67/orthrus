"""Password-reset token-leakage scanner (complements host-header poisoning).

``host_header.py`` covers reset-link *poisoning* (attacker-controlled Host in the
emailed link). This scanner covers the complementary flow bug: the reset
**token leaking back in the HTTP response** instead of being delivered only by
email. When a "forgot password" request returns the reset link/token in its
response body or in a redirect ``Location``, anyone who can see that response (or
the Referer it leaks into) can reset the account - straight to takeover.

The probe submits a reset request for a benign, non-deliverable test address
(``@example.com``) and looks for a reset URL carrying a token, or a token-named
field, in the response or the ``Location`` header. Detection is deterministic and
context-scoped (the URL/field must be reset-related) to keep false positives low.
Active - runs at NORMAL aggressiveness; read-mostly (a reset for a throwaway
address). Scope-enforced throughout.
"""

from __future__ import annotations

import re
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
    Severity,
)
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.password-reset")

SCANNER_NAME = "password-reset-leak"
MAX_TARGETS = 8
_PROBE_EMAIL = "orthrus.reset.probe@example.com"  # reserved TLD -> never delivered

_RESET_PATH_HINTS = (
    "reset", "forgot", "recover", "lostpassword", "lost-password",
    "forgotpassword", "resetpassword", "password/forgot", "password/reset",
)
_EMAIL_PARAM_HINTS = ("email", "mail", "username", "user", "login", "account")

# A reset URL (path mentions reset/recover/forgot/confirm/verify) carrying a
# token-ish param with a substantial value - i.e. the emailed link, returned
# in-band. The context requirement is what keeps this low-false-positive.
_RESET_LINK_RE = re.compile(
    r"""https?://[^\s"'<>]*(?:reset|recover|forgot|confirm|verify)[^\s"'<>]*"""
    r"""[?&][A-Za-z0-9_]*(?:token|code|key|t)=([A-Za-z0-9._~\-]{12,})""",
    re.I,
)
# A JSON/HTML field explicitly named like a reset token, with a high-entropy value.
_TOKEN_FIELD_RE = re.compile(
    r"""["']?(?:reset[_-]?token|reset[_-]?code|password[_-]?token|token|otp|code)["']?"""
    r"""\s*[:=]\s*["']([A-Za-z0-9._~\-]{16,})["']""",
    re.I,
)


def is_reset_endpoint(path: str) -> bool:
    lpath = path.lower()
    return any(h in lpath for h in _RESET_PATH_HINTS)


def _is_email_param(name: str) -> bool:
    low = name.lower()
    return any(h in low for h in _EMAIL_PARAM_HINTS)


def find_reset_token_leak(body: str, location: str = "") -> str | None:
    """Return the leaked reset token if the response/redirect exposes one."""
    for text in (location or "", body or ""):
        m = _RESET_LINK_RE.search(text)
        if m:
            return m.group(1)
    m2 = _TOKEN_FIELD_RE.search(body or "")
    if m2:
        return m2.group(1)
    return None


@register
class PasswordResetLeakScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "password-reset-leak"
    min_aggressiveness = Aggressiveness.NORMAL

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen: set[tuple[str, str]] = set()
        tested = 0
        for ep in ctx.endpoints:
            path = urlsplit(ep.url).path
            if not is_reset_endpoint(path):
                continue
            key = (ep.method.value, path)
            if key in seen or not ctx.scope.is_allowed(ep.url):
                continue
            seen.add(key)
            if tested >= MAX_TARGETS:
                break
            tested += 1

            resp = await self._submit_reset(ctx, ep)
            if resp is None:
                continue
            location = resp.headers.get("location", "") if hasattr(resp, "headers") else ""
            token = find_reset_token_leak(resp.text, location)
            if token is not None:
                yield self._finding(ep.url, ep.method, token, bool(location and token in location))

    async def _submit_reset(self, ctx: ScanContext, ep: object) -> httpx.Response | None:
        url = ep.url  # type: ignore[attr-defined]
        method = ep.method  # type: ignore[attr-defined]
        try:
            if method == HttpMethod.POST:
                data = self._reset_form(ep)
                return await ctx.http.request("POST", url, data=data, follow_redirects=False)
            return await ctx.http.request("GET", url, follow_redirects=False)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL, ValueError, UnicodeError) as exc:
            logger.debug("password-reset probe failed for %s: %s", url, exc)
            return None

    def _reset_form(self, ep: object) -> dict[str, str]:
        params = getattr(ep, "params", None) or []
        data: dict[str, str] = {}
        for p in params:
            data[p.name] = _PROBE_EMAIL if _is_email_param(p.name) else (p.value or "orthrus")
        if not any(_is_email_param(k) for k in data):
            data["email"] = _PROBE_EMAIL
        return data

    def _finding(
        self, url: str, method: HttpMethod, token: str, via_location: bool
    ) -> Finding:
        where = "the redirect Location header" if via_location else "the response body"
        preview = token[:6] + "…" if len(token) > 6 else token
        return Finding(
            vuln_type="password-reset-leak",
            title="Password-reset token leaked in the HTTP response",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            url=url,
            description=(
                f"A password-reset request to {url} returned a reset token in {where} rather than "
                "delivering it only by email. Any party able to observe the response - or the URL "
                "once it leaks into a Referer header, browser history, proxy, or log - can complete "
                "the reset and take over the account (CWE-640). Confirm the token is a usable reset "
                "credential."
            ),
            remediation=(
                "Never return the reset token or reset link in the HTTP response; deliver it only "
                "out-of-band by email. Make tokens single-use, short-lived, and high-entropy, and "
                "avoid placing them in URLs that leak via Referer."
            ),
            cwe="CWE-640",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                request_raw=f"{method.value} {url}  (reset for {_PROBE_EMAIL})",
                matched_at=f"token {preview} in {where}",
                notes="reset token/link returned in-band instead of email-only",
            ),
        )


__all__ = [
    "PasswordResetLeakScanner",
    "is_reset_endpoint",
    "find_reset_token_leak",
]
