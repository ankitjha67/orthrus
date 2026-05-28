"""Default-credential testing (PRD §6.6).

Identifies login forms and tries a small list of common default credentials,
comparing each attempt against a known-bad baseline to detect a successful
login (redirect or loss of the failure signature).
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator

import httpx

from hydra.core.context import ScanContext
from hydra.core.schemas import Confidence, Evidence, Finding, HttpMethod, ParamLocation, Severity
from hydra.scanners.base_scanner import BaseScanner
from hydra.scanners.registry import register
from hydra.utils.scope import ScopeViolation

SCANNER_NAME = "default-credentials"

USER_FIELDS = {"username", "user", "email", "login", "uname", "userid", "user_name"}
PASS_FIELDS = {"password", "pass", "passwd", "pwd", "passwize"}
_FAIL_MARKERS = ("invalid", "incorrect", "failed", "wrong", "denied", "try again", "bad credentials")

CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("admin", "123456"), ("admin", ""), ("administrator", "password"),
    ("root", "root"), ("root", "toor"), ("test", "test"),
    ("user", "user"), ("guest", "guest"),
]


def find_login_fields(param_names: list[str]) -> tuple[str | None, str | None]:
    user = next((n for n in param_names if n.lower() in USER_FIELDS), None)
    pwd = next((n for n in param_names if n.lower() in PASS_FIELDS), None)
    return user, pwd


def looks_like_success(
    baseline_status: int, baseline_body: str, status: int, body: str
) -> bool:
    if status in (301, 302, 303) and baseline_status not in (301, 302, 303):
        return True
    low = body.lower()
    baseline_low = baseline_body.lower()
    baseline_failed = any(m in baseline_low for m in _FAIL_MARKERS)
    attempt_failed = any(m in low for m in _FAIL_MARKERS)
    return baseline_failed and not attempt_failed and status < 400


@register
class DefaultCredentialsScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "default-creds"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        for ep in ctx.endpoints:
            if ep.method != HttpMethod.POST or ep.source != "form":
                continue
            names = [p.name for p in ep.params if p.location == ParamLocation.BODY]
            user_field, pass_field = find_login_fields(names)
            if not user_field or not pass_field or ep.url in seen:
                continue
            seen.add(ep.url)

            base = {p.name: (p.value or "x") for p in ep.params if p.location == ParamLocation.BODY}
            wrong = {**base, user_field: f"no_{secrets.token_hex(4)}", pass_field: secrets.token_hex(8)}
            baseline = await self._post(ctx, ep.url, wrong)
            if baseline is None:
                continue

            for username, password in CREDENTIALS:
                attempt = {**base, user_field: username, pass_field: password}
                resp = await self._post(ctx, ep.url, attempt)
                if resp is None:
                    continue
                if looks_like_success(baseline.status_code, baseline.text, resp.status_code, resp.text):
                    yield Finding(
                        vuln_type="default-creds",
                        title=f"Default credentials accepted: {username}/{password or '(empty)'}",
                        severity=Severity.HIGH,
                        confidence=Confidence.FIRM,
                        url=ep.url,
                        parameter=user_field,
                        param_location=ParamLocation.BODY,
                        description=(
                            f"The login form accepted default credentials "
                            f"'{username}:{password}', granting access."
                        ),
                        remediation=(
                            "Force a password change on first login, forbid known default "
                            "credentials, and add rate limiting / lockout."
                        ),
                        cwe="CWE-1392",
                        scanner=SCANNER_NAME,
                        evidence=Evidence(
                            request_raw=f"{user_field}={username}&{pass_field}={password}",
                            notes=f"baseline HTTP {baseline.status_code} -> attempt HTTP {resp.status_code}",
                        ),
                    )
                    break

    async def _post(self, ctx: ScanContext, url: str, data: dict) -> httpx.Response | None:
        try:
            return await ctx.http.post(url, data=data, follow_redirects=False)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL):
            return None


__all__ = ["DefaultCredentialsScanner", "find_login_fields", "looks_like_success"]
