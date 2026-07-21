"""OTP / 2FA security scanner.

OTP-gated login and withdrawal flows are the crown jewels of a betting platform, and
the two flaws that break them are mechanical:

* **No brute-force protection.** A 4-6 digit code has 10^4-10^6 possibilities; without
  rate-limiting or lockout an attacker walks the space. Detected by a bounded micro-burst
  of *wrong* codes: if none are throttled, the guard is absent.
* **Client-trusted result.** The verify endpoint returns the outcome as a body boolean
  (``{"success":false}``) that a client trusts, inviting the classic false -> true tamper.
  Flagged (tentatively) when a wrong code returns 200 with such a body.

Both probes send only invalid codes (non-destructive) and run only in aggressive mode.
"""

from __future__ import annotations

import re
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
from orthrus.scanners._authflow import OTP_PARAMS, any_throttled, is_otp_endpoint, micro_burst
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register

SCANNER_NAME = "otp-2fa"
MAX_ENDPOINTS = 5
OTP_BURST = 10
WRONG_OTP = "000000"  # a benign, almost-certainly-wrong code

# A body that carries the verification result as a client-readable boolean/flag.
_CLIENT_RESULT = re.compile(
    r"""["']?(success|valid|verified|status|result|authenticated|ok)["']?\s*[:=]\s*"""
    r"""(false|"false"|"failed"|"error"|"invalid"|0)\b""",
    re.IGNORECASE,
)


def client_trusted_result(status: int, body: str) -> bool:
    """True if a wrong code returns 200 with the outcome as a body boolean/flag."""
    return 200 <= status < 300 and bool(_CLIENT_RESULT.search(body or ""))


@register
class OtpScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "otp-security"
    min_aggressiveness = Aggressiveness.AGGRESSIVE  # sends bounded bursts of wrong codes

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        tested = 0
        seen: set[str] = set()
        for ep in ctx.endpoints:
            if tested >= MAX_ENDPOINTS:
                break
            if ep.method not in (HttpMethod.POST, HttpMethod.PUT):
                continue
            body_params = [p for p in ep.params if p.location in (ParamLocation.BODY, ParamLocation.JSON)]
            names = [p.name for p in body_params]
            if not is_otp_endpoint(ep.url, names):
                continue
            key = urlsplit(ep.url).path
            if key in seen or not ctx.scope.is_allowed(ep.url):
                continue
            seen.add(key)
            tested += 1

            is_json = any(p.location == ParamLocation.JSON for p in body_params)
            wrong = {
                p.name: (WRONG_OTP if p.name.lower() in OTP_PARAMS else (p.value or "orthrus"))
                for p in body_params
            } or {"otp": WRONG_OTP}

            results = await micro_burst(
                ctx, ep.method.value, ep.url,
                data=None if is_json else wrong, json=wrong if is_json else None, n=OTP_BURST,
            )
            answered = [(s, b) for s, b in results if s]
            if not answered:
                continue

            status0, body0 = answered[0]
            if client_trusted_result(status0, body0):
                yield self._client_trusted_finding(ep, status0)

            if len(answered) >= max(3, OTP_BURST - 2) and not any_throttled(results):
                yield self._brute_finding(ep, len(answered))

    def _brute_finding(self, ep: object, answered: int) -> Finding:
        return Finding(
            vuln_type="otp-security",
            title=f"No brute-force protection on OTP verification at {urlsplit(ep.url).path}",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            url=ep.url,
            description=(
                f"A burst of {answered} wrong one-time codes was accepted for processing with no "
                "throttling, lockout, or challenge. A short numeric OTP (10^4-10^6 values) with no "
                "brute-force guard can be walked exhaustively, defeating the second factor on "
                "login and - on this class of target - withdrawal authorization (account/funds "
                "takeover)."
            ),
            remediation=(
                "Rate-limit and lock OTP verification per account and per IP (e.g. 5 attempts then "
                "a cooldown), expire codes quickly, invalidate a code after the first failed burst, "
                "and add a CAPTCHA/step-up after repeated failures."
            ),
            cwe="CWE-307",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                request_raw=f"{answered}x wrong OTP -> {ep.method.value} {urlsplit(ep.url).path}",
                notes="no 429 / lockout / challenge observed across the burst",
            ),
        )

    def _client_trusted_finding(self, ep: object, status: int) -> Finding:
        return Finding(
            vuln_type="otp-security",
            title=f"OTP result returned as a client-readable flag at {urlsplit(ep.url).path}",
            severity=Severity.MEDIUM,
            confidence=Confidence.TENTATIVE,
            url=ep.url,
            description=(
                "A wrong OTP returned HTTP 200 with the verification outcome carried as a body "
                "boolean/flag (e.g. success:false). If any client flow trusts that flag, or the "
                "endpoint does not also enforce the result server-side, an attacker can flip the "
                "response false -> true to bypass the second factor. Manually confirm the result "
                "is enforced server-side and not merely reflected in the body."
            ),
            remediation=(
                "Decide OTP validity server-side and gate the protected action on server state, "
                "never on a value the client can rewrite; return an error status for a wrong code."
            ),
            cwe="CWE-603",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                request_raw=f"wrong OTP -> HTTP {status} with a result flag in the body",
                notes="verification outcome appears in the response body as a client-trusted flag",
            ),
        )


__all__ = ["OtpScanner", "client_trusted_result", "SCANNER_NAME"]
