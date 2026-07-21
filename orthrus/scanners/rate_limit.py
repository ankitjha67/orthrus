"""Rate-limit / abuse scanner for sensitive actions.

Missing throttling on a sensitive action is a finding in its own right: it enables
credential stuffing on login, password-reset flooding, voucher/bonus farming, and
generally makes every other abuse cheaper. This fires a bounded micro-burst of
invalid requests at login / password-reset / registration / voucher / bonus endpoints
and flags the ones where no throttling, lockout, or challenge ever engages.

OTP verification is deliberately excluded here - the ``otp-2fa`` scanner owns it with
a brute-force framing. The burst is capped and sends invalid inputs only: it detects
the *absence* of a control, it is not a load test.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

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
from orthrus.scanners._authflow import any_throttled, classify_action, micro_burst
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register

SCANNER_NAME = "rate-limit"
MAX_ENDPOINTS = 6
BURST = 12

# How much a missing limit matters, by action.
_SEVERITY = {
    "login": Severity.HIGH,             # credential stuffing / account takeover
    "password-reset": Severity.HIGH,    # reset flooding / token brute
    "register": Severity.MEDIUM,        # mass account creation
    "voucher": Severity.MEDIUM,         # code farming / brute
    "bonus": Severity.MEDIUM,           # promo abuse
}


@register
class RateLimitScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "missing-rate-limit"
    min_aggressiveness = Aggressiveness.AGGRESSIVE  # sends bounded bursts

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        tested = 0
        seen: set[tuple[str, str]] = set()
        for ep in ctx.endpoints:
            if tested >= MAX_ENDPOINTS:
                break
            if ep.method not in (HttpMethod.POST, HttpMethod.PUT):
                continue
            body_params = [p for p in ep.params if p.location in (ParamLocation.BODY, ParamLocation.JSON)]
            action = classify_action(ep.url, [p.name for p in body_params])
            if action is None or action == "otp":
                continue  # unknown action, or OTP (owned by otp-2fa)
            key = (action, urlsplit(ep.url).path)
            if key in seen or not ctx.scope.is_allowed(ep.url):
                continue
            seen.add(key)
            tested += 1

            is_json = any(p.location == ParamLocation.JSON for p in body_params)
            body = {p.name: (p.value or "orthrus") for p in body_params} or {"q": "orthrus"}
            results = await micro_burst(
                ctx, ep.method.value, ep.url,
                data=None if is_json else body, json=body if is_json else None, n=BURST,
            )
            answered = [(s, b) for s, b in results if s]
            if len(answered) >= max(3, BURST - 2) and not any_throttled(results):
                yield self._finding(ep, action, len(answered))

    def _finding(self, ep: object, action: str, answered: int) -> Finding:
        label = action.replace("-", " ")
        return Finding(
            vuln_type="missing-rate-limit",
            title=f"Missing rate limiting on {label} at {urlsplit(ep.url).path}",
            severity=_SEVERITY.get(action, Severity.MEDIUM),
            confidence=Confidence.FIRM,
            url=ep.url,
            description=(
                f"A burst of {answered} requests to this {label} endpoint was accepted with no "
                "throttling, lockout, or challenge. Without a rate limit this action can be "
                "automated at scale - credential stuffing, reset/OTP flooding, or "
                "voucher/bonus farming depending on the endpoint."
            ),
            remediation=(
                "Enforce per-account and per-IP rate limits with exponential backoff/lockout on "
                "authentication and value-bearing actions, and add a CAPTCHA or proof-of-work "
                "step-up after repeated attempts."
            ),
            cwe="CWE-799",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                request_raw=f"{answered}x {ep.method.value} {urlsplit(ep.url).path} ({label})",
                notes="no 429 / lockout / challenge observed across the burst",
            ),
        )


__all__ = ["RateLimitScanner", "SCANNER_NAME"]
