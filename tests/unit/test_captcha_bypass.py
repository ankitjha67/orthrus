"""CAPTCHA-enforcement (bypass) scanner + confirmer."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import httpx

from orthrus.core.schemas import (
    Confidence,
    Endpoint,
    Evidence,
    Finding,
    HttpMethod,
    Param,
    ParamLocation,
    Severity,
)
from orthrus.exploits.captcha_bypass_confirm import CaptchaBypassConfirm
from orthrus.scanners.captcha_bypass import (
    CaptchaBypassScanner,
    captcha_bypassed,
    has_captcha_error,
)


# ----------------------------------------------------------------- detectors
def test_has_captcha_error() -> None:
    assert has_captcha_error("Invalid captcha. Try again.") is True
    assert has_captcha_error("Welcome back!") is False


def test_captcha_bypassed_differential() -> None:
    assert captcha_bypassed("invalid captcha", "welcome, account created") is True
    assert captcha_bypassed("invalid captcha", "invalid captcha") is False  # both rejected
    assert captcha_bypassed("welcome", "welcome") is False  # no control rejection


# ------------------------------------------------------------------- scanner
def _endpoint() -> Endpoint:
    return Endpoint(
        url="http://h/register",
        method=HttpMethod.POST,
        params=[
            Param(name="username", location=ParamLocation.BODY, value=""),
            Param(name="captcha_token", location=ParamLocation.BODY, value=""),
        ],
    )


class CaptchaHttp:
    """Rejects an invalid token but accepts a submission with the token omitted."""

    def __init__(self, *, enforced: bool) -> None:
        self.enforced = enforced

    async def post(self, url: str, data: dict | None = None, **kw: object) -> httpx.Response:
        data = data or {}
        if "captcha_token" in data:  # invalid token present -> rejected
            body = "Invalid captcha. Please try again."
        elif self.enforced:
            body = "Captcha required."  # omission also rejected (properly enforced)
        else:
            body = "Welcome, your account was created."  # omission accepted -> bypass
        return httpx.Response(200, text=body, request=httpx.Request("POST", url))


def _ctx(http: object) -> SimpleNamespace:
    return SimpleNamespace(
        endpoints=[_endpoint()],
        http=http,
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(target="http://h/"),
    )


def _scan(ctx: SimpleNamespace) -> list[Finding]:
    async def run():
        return [f async for f in CaptchaBypassScanner().scan(ctx)]

    return asyncio.run(run())


def test_scanner_flags_omission_bypass() -> None:
    findings = _scan(_ctx(CaptchaHttp(enforced=False)))
    cb = [f for f in findings if f.vuln_type == "captcha-bypass"]
    assert len(cb) == 1
    assert cb[0].confidence == Confidence.TENTATIVE
    assert cb[0].severity == Severity.MEDIUM


def test_scanner_quiet_when_enforced() -> None:
    findings = _scan(_ctx(CaptchaHttp(enforced=True)))
    assert [f for f in findings if f.vuln_type == "captcha-bypass"] == []


# ----------------------------------------------------------------- confirmer
def _finding() -> Finding:
    return Finding(
        vuln_type="captcha-bypass",
        title="CAPTCHA not enforced",
        severity=Severity.MEDIUM,
        confidence=Confidence.TENTATIVE,
        url="http://h/register",
        parameter="captcha_token",
        param_location=ParamLocation.BODY,
        cwe="CWE-693",
        scanner="captcha-bypass",
        evidence=Evidence(),
    )


def test_confirmer_reproduces_differential() -> None:
    ctx = _ctx(CaptchaHttp(enforced=False))
    result = asyncio.run(CaptchaBypassConfirm().confirm(ctx, _finding()))
    assert result.success is True
    assert result.extracted_data == "captcha_token"


def test_confirmer_fails_when_enforced() -> None:
    ctx = _ctx(CaptchaHttp(enforced=True))
    result = asyncio.run(CaptchaBypassConfirm().confirm(ctx, _finding()))
    assert result.success is False
