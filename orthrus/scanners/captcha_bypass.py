"""CAPTCHA-enforcement scanner (missing server-side verification).

A CAPTCHA only protects if the *server* rejects a request whose CAPTCHA token is
missing or invalid. A common flaw: the endpoint validates a *wrong* token but
lets a request through when the token field is simply **omitted** (client-side-
only gate, or a verification step that no-ops on absent input).

This scanner submits a CAPTCHA-guarded form twice - once with a deliberately
invalid token, once with the token field removed - and flags the **differential**:
the invalid submission is rejected with a CAPTCHA-failure message while the
omitted submission is not. That inconsistency is a deterministic signal the gate
is not enforced on omission; the downstream action's success still needs manual
confirmation, so findings are TENTATIVE.

Intrusive (it POSTs the form), so it runs only at AGGRESSIVE aggressiveness.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import (
    Aggressiveness,
    Confidence,
    Endpoint,
    Evidence,
    Finding,
    HttpMethod,
    ParamLocation,
    Severity,
)
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.captcha-bypass")

SCANNER_NAME = "captcha-bypass"
MAX_TARGETS = 12
_INVALID_TOKEN = "orthrus_invalid_captcha_000"

_CAPTCHA_PARAM_HINTS = (
    "g-recaptcha-response", "h-captcha-response", "cf-turnstile-response",
    "captcha", "captcha_token", "captcha_answer", "captcha_response", "recaptcha",
    "hcaptcha", "turnstile",
)

# Phrases that specifically indicate a CAPTCHA *rejection* (not just widget
# presence) - required in the invalid-token control before we conclude anything.
_CAPTCHA_FAIL_MARKERS = (
    "captcha verification failed", "captcha failed", "invalid captcha",
    "incorrect captcha", "captcha required", "captcha is required",
    "please complete the captcha", "recaptcha verification failed",
    "verify you are human", "are you a robot", "captcha token missing",
    "captcha error", "failed captcha", "robot check failed",
)


def _captcha_param(params: list) -> str | None:
    for p in params:
        if any(hint == p.name.lower() or hint in p.name.lower() for hint in _CAPTCHA_PARAM_HINTS):
            return p.name
    return None


def has_captcha_error(body: str) -> bool:
    low = (body or "").lower()
    return any(marker in low for marker in _CAPTCHA_FAIL_MARKERS)


def captcha_bypassed(invalid_body: str, omitted_body: str) -> bool:
    """The server rejects an invalid token but not a missing one - enforcement gap."""
    return has_captcha_error(invalid_body) and not has_captcha_error(omitted_body)


@register
class CaptchaBypassScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "captcha-bypass"
    min_aggressiveness = Aggressiveness.AGGRESSIVE

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen: set[tuple[str, str]] = set()
        tested = 0
        for ep in ctx.endpoints:
            if ep.method != HttpMethod.POST:
                continue
            cap = _captcha_param(ep.params)
            if cap is None:
                continue
            key = (urlsplit(ep.url).netloc, urlsplit(ep.url).path)
            if key in seen or not ctx.scope.is_allowed(ep.url):
                continue
            seen.add(key)
            if tested >= MAX_TARGETS:
                break
            tested += 1

            invalid = await self._post(ctx, ep, cap, invalid=True)
            omitted = await self._post(ctx, ep, cap, invalid=False)
            if invalid is None or omitted is None:
                continue
            if captcha_bypassed(invalid.text, omitted.text):
                yield self._finding(ep.url, cap)

    async def _post(
        self, ctx: ScanContext, ep: Endpoint, captcha_param: str, *, invalid: bool
    ) -> httpx.Response | None:
        data: dict[str, str] = {}
        for p in ep.params:
            if p.location != ParamLocation.BODY:
                continue
            if p.name == captcha_param:
                if invalid:
                    data[p.name] = _INVALID_TOKEN
                # else: omit the captcha field entirely
                continue
            data[p.name] = p.value or "orthrus"
        try:
            return await ctx.http.post(ep.url, data=data, follow_redirects=False)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL, ValueError, UnicodeError) as exc:
            logger.debug("captcha-bypass probe failed for %s: %s", ep.url, exc)
            return None

    def _finding(self, url: str, captcha_param: str) -> Finding:
        return Finding(
            vuln_type="captcha-bypass",
            title=f"CAPTCHA not enforced server-side on omission ({urlsplit(url).path})",
            severity=Severity.MEDIUM,
            confidence=Confidence.TENTATIVE,
            url=url,
            parameter=captcha_param,
            param_location=ParamLocation.BODY,
            description=(
                f"The form at {url} rejects a submission with an invalid '{captcha_param}' token "
                "(CAPTCHA-failure response) but not one where the token field is omitted entirely - "
                "so the CAPTCHA is validated only when present and can be skipped by removing the "
                "field. That defeats the anti-automation control (enabling brute-force, spam, or "
                "credential stuffing). Confirm the underlying action actually completes without the "
                "CAPTCHA."
            ),
            remediation=(
                "Require and verify the CAPTCHA token server-side on every submission; treat a "
                "missing token exactly like an invalid one (reject). Bind verification to the action "
                "and enforce single-use tokens."
            ),
            cwe="CWE-693",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                request_raw=f"POST {url}  (omit '{captcha_param}')",
                matched_at=captcha_param,
                notes="invalid-token submission rejected with a CAPTCHA error; omitted-token was not",
            ),
        )


__all__ = [
    "CaptchaBypassScanner",
    "has_captcha_error",
    "captcha_bypassed",
]
