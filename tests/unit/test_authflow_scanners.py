"""Auth-flow abuse scanners: OTP/2FA, rate-limit, account enumeration.

All three probe with a bounded micro-burst or a single invalid request and flag the
*absence* of a control. Duck-typed fakes keep the tests offline.
"""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Endpoint, HttpMethod, Param, ParamLocation, Severity
from orthrus.scanners._authflow import classify_action, is_throttled
from orthrus.scanners.account_enum import AccountEnumScanner, reveals_existence
from orthrus.scanners.otp_2fa import OtpScanner, client_trusted_result
from orthrus.scanners.rate_limit import RateLimitScanner


# ------------------------------------------------------------ classifier
def test_classify_action_precedence():
    assert classify_action("https://t/api/login", ["email", "password"]) == "login"
    assert classify_action("https://t/verify-otp", ["otp"]) == "otp"
    assert classify_action("https://t/verify", ["code"]) == "otp"
    assert classify_action("https://t/voucher/redeem", ["code"]) == "voucher"   # path beats 'code'
    assert classify_action("https://t/bonus/claim", ["code"]) == "bonus"
    assert classify_action("https://t/password/reset", ["email"]) == "password-reset"
    assert classify_action("https://t/login", ["username", "otp"]) == "otp"     # strong param beats login
    assert classify_action("https://t/search", ["q"]) is None


def test_is_throttled_signals():
    assert is_throttled(429, "") is True
    assert is_throttled(503, "") is True
    assert is_throttled(200, "Too many attempts, slow down") is True
    assert is_throttled(200, "please complete the captcha") is True
    assert is_throttled(401, "invalid credentials") is False


# ------------------------------------------------------------ fakes
class _Resp:
    def __init__(self, status: int, text: str = "") -> None:
        self.status_code = status
        self.text = text


class _Http:
    """Responds via a (method, url, call_index) -> _Resp callable."""

    def __init__(self, responder) -> None:
        self._responder = responder
        self.calls = 0

    async def request(self, method: str, url: str, *, data=None, json=None,
                      follow_redirects: bool = False) -> _Resp:
        self.calls += 1
        return self._responder(method, url, self.calls)


def _ep(url: str, *params: tuple[str, str]) -> Endpoint:
    return Endpoint(url=url, method=HttpMethod.POST,
                    params=[Param(name=n, location=ParamLocation.BODY, value=v) for n, v in params])


def _ctx(endpoints, responder) -> SimpleNamespace:
    return SimpleNamespace(endpoints=endpoints, http=_Http(responder),
                           scope=SimpleNamespace(is_allowed=lambda _u: True))


# ------------------------------------------------------------ OTP scanner
def test_client_trusted_result_detects_body_flag():
    assert client_trusted_result(200, '{"success":false}') is True
    assert client_trusted_result(200, '{"verified": false, "msg": "bad"}') is True
    assert client_trusted_result(400, '{"success":false}') is False        # error status = fine
    assert client_trusted_result(200, '{"balance": 500}') is False


async def test_otp_flags_missing_brute_force_protection():
    ctx = _ctx([_ep("https://t/verify-otp", ("otp", "123456"))],
               lambda m, u, i: _Resp(400, "wrong code"))          # never throttles
    findings = [f async for f in OtpScanner().scan(ctx)]
    brute = [f for f in findings if "brute-force" in f.title]
    assert len(brute) == 1 and brute[0].severity == Severity.HIGH and brute[0].cwe == "CWE-307"


async def test_otp_no_finding_when_throttled():
    ctx = _ctx([_ep("https://t/verify-otp", ("otp", "1"))],
               lambda m, u, i: _Resp(429, "too many"))
    assert [f async for f in OtpScanner().scan(ctx)] == []


async def test_otp_flags_client_trusted_result_only():
    # 200+success:false on the first call, then throttle -> only the client-trusted finding.
    def responder(m, u, i):
        return _Resp(200, '{"success":false}') if i == 1 else _Resp(429, "slow down")
    findings = [f async for f in OtpScanner().scan(_ctx([_ep("https://t/2fa", ("otp", "1"))], responder))]
    assert len(findings) == 1 and "client-readable flag" in findings[0].title


# ------------------------------------------------------------ rate-limit scanner
async def test_rate_limit_flags_login_high():
    ctx = _ctx([_ep("https://t/api/login", ("email", "a@b.c"), ("password", "x"))],
               lambda m, u, i: _Resp(401, "invalid credentials"))
    (f,) = [x async for x in RateLimitScanner().scan(ctx)]
    assert f.vuln_type == "missing-rate-limit" and f.severity == Severity.HIGH


async def test_rate_limit_voucher_is_medium():
    ctx = _ctx([_ep("https://t/voucher/redeem", ("code", "ABC"))],
               lambda m, u, i: _Resp(400, "invalid voucher"))
    (f,) = [x async for x in RateLimitScanner().scan(ctx)]
    assert f.severity == Severity.MEDIUM


async def test_rate_limit_skips_when_throttled_and_skips_otp():
    throttled = _ctx([_ep("https://t/login", ("user", "a"))], lambda m, u, i: _Resp(429, ""))
    assert [x async for x in RateLimitScanner().scan(throttled)] == []
    otp = _ctx([_ep("https://t/verify-otp", ("otp", "1"))], lambda m, u, i: _Resp(200, "ok"))
    assert [x async for x in RateLimitScanner().scan(otp)] == []   # OTP owned by otp-2fa


# ------------------------------------------------------------ account enumeration
def test_reveals_existence_respects_safe_phrasing():
    assert reveals_existence("User not found") == "not found"
    assert reveals_existence("That email is already registered") == "already registered"
    assert reveals_existence("Invalid credentials") is None                 # generic = safe
    assert reveals_existence("If an account exists we sent a link") is None  # safe even w/ hints


async def test_account_enum_flags_user_not_found():
    ctx = _ctx([_ep("https://t/api/login", ("email", "a@b.c"), ("password", "x"))],
               lambda m, u, i: _Resp(401, "No account with that email"))
    (f,) = [x async for x in AccountEnumScanner().scan(ctx)]
    assert f.vuln_type == "account-enumeration" and f.severity == Severity.MEDIUM


async def test_account_enum_silent_on_generic_error():
    ctx = _ctx([_ep("https://t/login", ("email", "a@b.c"), ("password", "x"))],
               lambda m, u, i: _Resp(401, "Invalid username or password"))
    assert [x async for x in AccountEnumScanner().scan(ctx)] == []
