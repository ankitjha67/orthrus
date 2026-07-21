"""Shared helpers for the auth-flow abuse scanners (OTP, rate-limit, account-enum).

These scanners share two needs: recognise a *sensitive action* endpoint (login,
password reset, OTP verification, voucher/bonus redemption, registration) from its
path and parameters, and fire a **bounded, measured micro-burst** to see whether the
server throttles. The burst is deliberately tiny (a dozen requests, hard-capped) and
sends only invalid inputs - it probes for the *absence* of a control, it is not a DoS.
Every request goes through the scope-enforced client.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.utils.scope import ScopeViolation

BURST_CAP = 15  # hard ceiling on any single burst - stays well clear of DoS territory

# Path fragments that mark each sensitive action.
_ACTION_PATHS: dict[str, tuple[str, ...]] = {
    "otp": ("otp", "2fa", "mfa", "verify", "verification", "confirm-code", "totp", "one-time"),
    "login": ("login", "signin", "sign-in", "authenticate", "session", "log-in"),
    "register": ("register", "signup", "sign-up", "create-account", "join"),
    "password-reset": ("reset", "forgot", "recover", "forgot-password", "reset-password"),
    "voucher": ("voucher", "redeem", "coupon", "promo", "promo-code", "gift", "giftcard"),
    "bonus": ("bonus", "claim", "reward", "cashback", "loyalty"),
}

# Parameter names that mark an OTP/2FA verification field.
OTP_PARAMS = frozenset({
    "otp", "code", "pin", "otpcode", "otp_code", "2fa", "mfa", "token", "authcode",
    "auth_code", "verificationcode", "verification_code", "sms_code", "email_code",
    "onetimecode", "one_time_code", "otc", "securitycode", "security_code",
})
# Dedicated OTP params (excludes the ambiguous code/pin/token/otc, which also appear on
# voucher/redeem and generic forms) - a strong signal even on a login-ish path.
_STRONG_OTP_PARAMS = frozenset({
    "otp", "otpcode", "otp_code", "2fa", "mfa", "authcode", "auth_code",
    "verificationcode", "verification_code", "sms_code", "email_code",
    "onetimecode", "one_time_code", "securitycode", "security_code",
})

_THROTTLE_STATUS = frozenset({429, 503})
_THROTTLE_MARKERS = (
    "too many", "rate limit", "rate-limit", "slow down", "try again later",
    "temporarily locked", "locked out", "please wait", "throttl", "captcha",
)


def _path_params(url: str, param_names: list[str]) -> tuple[str, str]:
    return urlsplit(url).path.lower(), " ".join(param_names).lower()


def classify_action(url: str, param_names: list[str]) -> str | None:
    """Return the definitive sensitive-action label for an endpoint, or ``None``.

    Precedence resolves the ambiguity that a ``code`` param is both an OTP field and
    a voucher field: an explicit value/account path (voucher/bonus/reset/register)
    wins first, then a strong OTP signal (OTP path or a *dedicated* OTP param), then
    login, and only last does a bare ambiguous ``code``/``pin``/``token`` count as OTP.
    """
    path, _params = _path_params(url, param_names)
    names = {n.lower() for n in param_names}
    for action in ("voucher", "bonus", "password-reset", "register"):
        if any(f in path for f in _ACTION_PATHS[action]):
            return action
    if any(f in path for f in _ACTION_PATHS["otp"]) or names & _STRONG_OTP_PARAMS:
        return "otp"
    if any(f in path for f in _ACTION_PATHS["login"]):
        return "login"
    if names & OTP_PARAMS:
        return "otp"
    return None


def is_otp_endpoint(url: str, param_names: list[str]) -> bool:
    """True if the endpoint is an OTP/2FA verification step (definitive classification)."""
    return classify_action(url, param_names) == "otp"


def is_throttled(status: int, body: str) -> bool:
    """True if a response reads as rate-limiting / lockout / a challenge."""
    if status in _THROTTLE_STATUS:
        return True
    low = (body or "").lower()
    return any(marker in low for marker in _THROTTLE_MARKERS)


def any_throttled(results: list[tuple[int, str]]) -> bool:
    return any(is_throttled(status, body) for status, body in results)


async def micro_burst(
    ctx: ScanContext,
    method: str,
    url: str,
    *,
    data: dict | None = None,
    json: dict | None = None,
    n: int = 12,
) -> list[tuple[int, str]]:
    """Fire ``n`` (capped) concurrent requests; return each (status, truncated body).

    Errors resolve to ``(0, "")`` so a partial network failure never crashes the
    scan. This is the measured burst the abuse scanners use to detect *missing*
    throttling - it is bounded by ``BURST_CAP``.
    """
    n = max(2, min(n, BURST_CAP))

    async def one() -> tuple[int, str]:
        try:
            kwargs: dict = {"follow_redirects": False}
            if json is not None:
                kwargs["json"] = json
            elif data is not None:
                kwargs["data"] = data
            resp = await ctx.http.request(method, url, **kwargs)
            return resp.status_code, resp.text[:600]
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL):
            return 0, ""

    return list(await asyncio.gather(*[one() for _ in range(n)]))


__all__ = [
    "BURST_CAP",
    "OTP_PARAMS",
    "classify_action",
    "is_otp_endpoint",
    "is_throttled",
    "any_throttled",
    "micro_burst",
]
