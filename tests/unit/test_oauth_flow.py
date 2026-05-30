"""OAuth 2.0 / OIDC authorization-flow misconfiguration scanner."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Endpoint, HttpMethod, Severity
from orthrus.scanners.oauth_flow import OAuthFlowScanner, is_oauth_authorize, oauth_static_issues


# ----------------------------------------------------------------- detection
def test_is_oauth_authorize_by_path():
    assert is_oauth_authorize("https://idp/oauth2/authorize?x=1", set()) is True


def test_is_oauth_authorize_by_params():
    assert is_oauth_authorize("https://idp/go", {"response_type", "client_id", "redirect_uri"})


def test_is_oauth_authorize_false():
    assert is_oauth_authorize("https://h/login", {"user", "pass"}) is False


# ----------------------------------------------------------------- static issues
def test_missing_state_flagged():
    issues = oauth_static_issues({"response_type": "code", "client_id": "a", "code_challenge": "x"})
    assert any(i[3] == "CWE-352" for i in issues)


def test_implicit_flow_flagged():
    issues = oauth_static_issues({"response_type": "token", "state": "s"})
    assert any("implicit" in i[1].lower() for i in issues)


def test_code_without_pkce_flagged():
    issues = oauth_static_issues({"response_type": "code", "state": "s"})
    assert any("PKCE" in i[1] for i in issues)


def test_clean_code_pkce_state_has_no_static_issue():
    issues = oauth_static_issues({"response_type": "code", "state": "s", "code_challenge": "x"})
    assert issues == []


# ----------------------------------------------------------------- redirect_uri active
class _Resp:
    def __init__(self, status: int, location: str) -> None:
        self.status_code = status
        self.headers = {"location": location} if location else {}

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400


class _Http:
    def __init__(self, *, reflect_redirect: bool) -> None:
        self._reflect = reflect_redirect

    async def get(self, url: str, **kw: object) -> _Resp:
        if self._reflect and "orthrus-oauth-evil.example" in url:
            return _Resp(302, "https://orthrus-oauth-evil.example/cb?code=abc")
        return _Resp(302, "https://legit-app.example/cb")


def _ctx(http: object, url: str) -> SimpleNamespace:
    return SimpleNamespace(
        endpoints=[Endpoint(url=url, method=HttpMethod.GET)],
        http=http,
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(target="https://idp/"),
    )


async def test_scan_flags_open_redirect_uri():
    url = "https://idp/oauth2/authorize?response_type=code&client_id=a&redirect_uri=https://legit-app.example/cb&state=s&code_challenge=x"
    findings = [f async for f in OAuthFlowScanner().scan(_ctx(_Http(reflect_redirect=True), url))]
    redir = [f for f in findings if "redirect_uri" in f.title]
    assert len(redir) == 1
    assert redir[0].severity == Severity.HIGH
    assert redir[0].cwe == "CWE-601"


async def test_scan_no_redirect_finding_when_validated():
    url = "https://idp/oauth2/authorize?response_type=code&client_id=a&redirect_uri=https://legit-app.example/cb&state=s&code_challenge=x"
    findings = [f async for f in OAuthFlowScanner().scan(_ctx(_Http(reflect_redirect=False), url))]
    assert not any("redirect_uri" in f.title for f in findings)
