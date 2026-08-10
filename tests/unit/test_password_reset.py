"""Password-reset token-leakage scanner."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Endpoint, HttpMethod, Param, ParamLocation, Severity
from orthrus.scanners.password_reset import (
    PasswordResetLeakScanner,
    find_reset_token_leak,
    is_reset_endpoint,
)


# ----------------------------------------------------------------- detectors
def test_is_reset_endpoint() -> None:
    assert is_reset_endpoint("/account/forgot-password") is True
    assert is_reset_endpoint("/api/v1/password/reset") is True
    assert is_reset_endpoint("/users/recover") is True
    assert is_reset_endpoint("/login") is False


def test_find_leak_in_reset_link() -> None:
    body = "Thanks! Debug: https://h/reset-password?token=abcdef1234567890XYZ ok"
    assert find_reset_token_leak(body) == "abcdef1234567890XYZ"


def test_find_leak_in_token_field() -> None:
    body = '{"message":"sent","reset_token":"aaaaaaaaaaaaaaaa1111"}'
    assert find_reset_token_leak(body) == "aaaaaaaaaaaaaaaa1111"


def test_find_leak_in_location_header() -> None:
    loc = "https://h/account/recover?code=abcdef1234567890"
    assert find_reset_token_leak("", loc) == "abcdef1234567890"


def test_no_leak_on_generic_response() -> None:
    assert find_reset_token_leak("If the account exists, an email was sent.") is None


def test_non_reset_url_with_token_is_not_a_leak() -> None:
    # An analytics/tracking URL carrying a token is not a reset-link leak - the
    # URL context must be reset-related.
    assert find_reset_token_leak("<img src=https://h/track?token=abcdef1234567890>") is None


# ------------------------------------------------------------------- scanner
class ResetHttp:
    def __init__(self, body: str, location: str = "") -> None:
        self.body = body
        self.location = location

    async def request(self, method: str, url: str, **kw: object) -> SimpleNamespace:
        headers = {"location": self.location} if self.location else {}
        return SimpleNamespace(text=self.body, headers=headers, status_code=200)


def _ctx(http: object) -> SimpleNamespace:
    ep = Endpoint(
        url="http://h/forgot-password",
        method=HttpMethod.POST,
        params=[Param(name="email", location=ParamLocation.BODY, value="")],
    )
    return SimpleNamespace(
        endpoints=[ep],
        http=http,
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(target="http://h/"),
    )


async def test_scanner_flags_token_in_body() -> None:
    body = "Reset link: https://h/reset-password?token=abcdef1234567890TOKEN sent."
    findings = [f async for f in PasswordResetLeakScanner().scan(_ctx(ResetHttp(body)))]
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].cwe == "CWE-640"


async def test_scanner_flags_token_in_location() -> None:
    http = ResetHttp("Redirecting…", location="https://h/account/reset?code=abcdef1234567890")
    findings = [f async for f in PasswordResetLeakScanner().scan(_ctx(http))]
    assert len(findings) == 1
    assert "Location" in findings[0].description or "Location" in findings[0].evidence.matched_at


async def test_scanner_quiet_on_email_only_flow() -> None:
    http = ResetHttp("If that account exists, a password reset email has been sent.")
    findings = [f async for f in PasswordResetLeakScanner().scan(_ctx(http))]
    assert findings == []
