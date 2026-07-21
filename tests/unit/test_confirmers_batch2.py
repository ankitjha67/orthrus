"""Tests for the second batch of confirmers: ldap / xpath / csrf / default-creds /
oauth / file-upload / web-cache-deception / prompt-injection / websocket (CSWSH).

Each re-proves impact through a fresh, non-destructive probe and only upgrades a
finding to ``confirmed`` when the proof reproduces. Duck-typed fakes keep the tests
fully offline.
"""

from __future__ import annotations

import re
from types import SimpleNamespace

from orthrus.core.schemas import (
    Endpoint,
    Evidence,
    Finding,
    HttpMethod,
    Param,
    ParamLocation,
    Severity,
)
from orthrus.exploits import websocket_confirm as _ws_mod
from orthrus.exploits.csrf_confirm import CsrfConfirm
from orthrus.exploits.default_creds_confirm import DefaultCredsConfirm
from orthrus.exploits.file_upload_confirm import FileUploadConfirm
from orthrus.exploits.ldap_confirm import LdapConfirm
from orthrus.exploits.oauth_confirm import OAuthConfirm
from orthrus.exploits.prompt_injection_confirm import PromptInjectionConfirm
from orthrus.exploits.registry import EXPLOIT_REGISTRY, exploits_for
from orthrus.exploits.web_cache_deception_confirm import WebCacheDeceptionConfirm
from orthrus.exploits.websocket_confirm import WebSocketConfirm
from orthrus.exploits.xpath_confirm import XpathConfirm
from orthrus.scanners.oauth_flow import _ATTACKER_HOST
from orthrus.scanners.websocket import ATTACKER_ORIGIN


# --------------------------------------------------------------------- fakes
def _finding(vuln_type: str, **kw: object) -> Finding:
    base: dict = {
        "vuln_type": vuln_type,
        "title": f"{vuln_type} finding",
        "severity": Severity.HIGH,
        "url": "http://h/x",
    }
    base.update(kw)
    return Finding(**base)


class _Req:
    method = "GET"
    url = "http://h/x"
    headers: dict = {}


class _Resp:
    def __init__(self, text: str = "", headers: dict | None = None,
                 status_code: int = 200) -> None:
        self.text = text
        self.headers = headers or {}
        self.status_code = status_code
        self.http_version = "HTTP/1.1"
        self.request = _Req()

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400 and any(k.lower() == "location" for k in self.headers)


# --------------------------------------------------------------- registration
def test_batch2_confirmers_registered():
    for name in (
        "ldap-confirm", "xpath-confirm", "csrf-confirm", "default-creds-confirm",
        "oauth-confirm", "file-upload-confirm", "web-cache-deception-confirm",
        "prompt-injection-confirm", "websocket-confirm",
    ):
        assert name in EXPLOIT_REGISTRY


def test_batch2_routes_by_vuln_type():
    cases = {
        "ldap-injection": "ldap-confirm",
        "xpath-injection": "xpath-confirm",
        "csrf": "csrf-confirm",
        "default-creds": "default-creds-confirm",
        "oauth-misconfig": "oauth-confirm",
        "file-upload": "file-upload-confirm",
        "web-cache-deception": "web-cache-deception-confirm",
        "prompt-injection": "prompt-injection-confirm",
        "websocket": "websocket-confirm",
    }
    for vuln_type, name in cases.items():
        assert any(e.name == name for e in exploits_for(_finding(vuln_type))), vuln_type


# ------------------------------------------------------------- ldap / xpath
class _ErrHttp:
    def __init__(self, body: str) -> None:
        self._body = body

    async def get(self, url: str, *, follow_redirects: bool = True) -> _Resp:
        return _Resp(text=self._body)


async def test_ldap_confirm_success_on_directory_error():
    ctx = SimpleNamespace(http=_ErrHttp("javax.naming.directory.InvalidSearchFilterException"),
                          endpoints=[])
    f = _finding("ldap-injection", parameter="u", evidence=Evidence(request_raw="u=*)("))
    res = await LdapConfirm().confirm(ctx, f)
    assert res.success is True and res.technique == "error-based replay"


async def test_ldap_confirm_fail_without_error():
    ctx = SimpleNamespace(http=_ErrHttp("welcome"), endpoints=[])
    f = _finding("ldap-injection", parameter="u", evidence=Evidence(request_raw="u=*)("))
    assert (await LdapConfirm().confirm(ctx, f)).success is False


async def test_xpath_confirm_success_on_eval_error():
    ctx = SimpleNamespace(http=_ErrHttp("XPathException: Invalid expression"), endpoints=[])
    f = _finding("xpath-injection", parameter="q", evidence=Evidence(request_raw="q=' or '1'='1"))
    res = await XpathConfirm().confirm(ctx, f)
    assert res.success is True and res.extracted_data == "xpath-eval-error"


# ----------------------------------------------------------------- csrf
def _form_ep(url: str, *fields: str) -> Endpoint:
    return Endpoint(
        url=url, method=HttpMethod.POST,
        params=[Param(name=f, location=ParamLocation.BODY, value="x") for f in fields],
    )


async def test_csrf_confirm_success_when_no_token():
    ctx = SimpleNamespace(endpoints=[_form_ep("http://h/transfer", "amount", "to")])
    res = await CsrfConfirm().confirm(ctx, _finding("csrf", url="http://h/transfer"))
    assert res.success is True and res.extracted_data == "no-anti-csrf-token"


async def test_csrf_confirm_fail_when_token_present():
    ctx = SimpleNamespace(endpoints=[_form_ep("http://h/transfer", "amount", "csrf_token")])
    res = await CsrfConfirm().confirm(ctx, _finding("csrf", url="http://h/transfer"))
    assert res.success is False


async def test_csrf_confirm_falls_back_to_evidence_fields():
    ctx = SimpleNamespace(endpoints=[])  # not in inventory -> parse recorded field list
    f = _finding("csrf", url="http://h/t", evidence=Evidence(notes="form fields: amount, to"))
    assert (await CsrfConfirm().confirm(ctx, f)).success is True


# --------------------------------------------------------- default-creds
class _LoginHttp:
    """Wrong creds -> 200 login page; recorded creds -> 302 (success) or 200 (fail)."""

    def __init__(self, *, accepts: bool) -> None:
        self._accepts = accepts

    async def post(self, url: str, *, data: dict | None = None,
                   follow_redirects: bool = False) -> _Resp:
        user = (data or {}).get("username", "")
        if user.startswith("no_"):
            return _Resp(text="please sign in", status_code=200)          # baseline
        if self._accepts:
            return _Resp(headers={"location": "/dashboard"}, status_code=302)
        return _Resp(text="please sign in", status_code=200)


def _login_ctx(accepts: bool) -> SimpleNamespace:
    return SimpleNamespace(http=_LoginHttp(accepts=accepts),
                           endpoints=[_form_ep("http://h/login", "username", "password")])


def _creds_finding() -> Finding:
    return _finding("default-creds", url="http://h/login", parameter="username",
                    param_location=ParamLocation.BODY,
                    evidence=Evidence(request_raw="username=admin&password=admin"))


async def test_default_creds_confirm_success_on_relogin():
    res = await DefaultCredsConfirm().confirm(_login_ctx(accepts=True), _creds_finding())
    assert res.success is True and res.extracted_data == "admin:admin"


async def test_default_creds_confirm_fail_when_rejected():
    res = await DefaultCredsConfirm().confirm(_login_ctx(accepts=False), _creds_finding())
    assert res.success is False


# ----------------------------------------------------------------- oauth
class _OAuthHttp:
    def __init__(self, *, redirect_to_attacker: bool) -> None:
        self._evil = redirect_to_attacker

    async def get(self, url: str, *, follow_redirects: bool = False) -> _Resp:
        if self._evil:
            return _Resp(headers={"location": f"https://{_ATTACKER_HOST}/cb"}, status_code=302)
        return _Resp(text="login", status_code=200)


def _oauth_finding() -> Finding:
    return _finding("oauth-misconfig",
                    url="http://h/authorize?response_type=code&client_id=x&redirect_uri=https://app/cb",
                    evidence=Evidence(request_raw="redirect_uri=https://orthrus-oauth-evil.example/cb"))


async def test_oauth_confirm_success_on_attacker_redirect():
    ctx = SimpleNamespace(http=_OAuthHttp(redirect_to_attacker=True))
    res = await OAuthConfirm().confirm(ctx, _oauth_finding())
    assert res.success is True and _ATTACKER_HOST in res.extracted_data


async def test_oauth_confirm_fail_when_no_open_redirect():
    ctx = SimpleNamespace(http=_OAuthHttp(redirect_to_attacker=False))
    assert (await OAuthConfirm().confirm(ctx, _oauth_finding())).success is False


async def test_oauth_confirm_skips_static_finding():
    ctx = SimpleNamespace(http=_OAuthHttp(redirect_to_attacker=True))
    f = _finding("oauth-misconfig", url="http://h/authorize",
                 evidence=Evidence(matched_at="Missing PKCE"))  # no redirect_uri probe recorded
    assert (await OAuthConfirm().confirm(ctx, f)).success is False


# ------------------------------------------------------------- file-upload
class _UploadHttp:
    """mode: 'served' echoes a stored path and serves the canary back;
    'accepted' accepts without disclosing a URL; 'rejected' refuses."""

    def __init__(self, mode: str) -> None:
        self._mode = mode
        self._marker = ""

    async def post(self, url: str, *, files: dict | None = None,
                   follow_redirects: bool = True) -> _Resp:
        fname, content, _ctype = files["file"]
        self._marker = content.decode()
        if self._mode == "rejected":
            return _Resp(text="file type not allowed", status_code=400)
        if self._mode == "served":
            return _Resp(text=f'{{"stored":"/uploads/{fname}"}}', status_code=200)
        return _Resp(text="upload successful", status_code=200)  # accepted, no URL

    async def get(self, url: str, *, follow_redirects: bool = True) -> _Resp:
        return _Resp(text=self._marker)


async def test_file_upload_confirm_success_when_served():
    ctx = SimpleNamespace(http=_UploadHttp("served"))
    res = await FileUploadConfirm().confirm(ctx, _finding("file-upload", url="http://h/upload"))
    assert res.success is True and res.extracted_data.endswith(".txt")
    assert "/uploads/" in res.extracted_data


async def test_file_upload_confirm_fail_when_no_url_disclosed():
    ctx = SimpleNamespace(http=_UploadHttp("accepted"))
    res = await FileUploadConfirm().confirm(ctx, _finding("file-upload", url="http://h/upload"))
    assert res.success is False and "stored URL" in (res.evidence.notes or "")


async def test_file_upload_confirm_fail_when_rejected():
    ctx = SimpleNamespace(http=_UploadHttp("rejected"))
    res = await FileUploadConfirm().confirm(ctx, _finding("file-upload", url="http://h/upload"))
    assert res.success is False


# ----------------------------------------------------- web-cache-deception
class _WcdHttp:
    def __init__(self, *, verbatim: bool) -> None:
        self._verbatim = verbatim

    async def get(self, url: str, *, follow_redirects: bool = True) -> _Resp:
        if "orthrus-wcd" in url:  # the deceptive static URL
            body = "PRIVATE DASHBOARD userid=7" if self._verbatim else "/* 404 */"
            return _Resp(text=body, headers={"cache-control": "public, max-age=60"})
        return _Resp(text="PRIVATE DASHBOARD userid=7")  # the dynamic base page


def _wcd_finding() -> Finding:
    return _finding("web-cache-deception", url="http://h/account/orthrus-wcd-abc123.css")


async def test_wcd_confirm_success_when_verbatim_and_cacheable():
    ctx = SimpleNamespace(http=_WcdHttp(verbatim=True))
    res = await WebCacheDeceptionConfirm().confirm(ctx, _wcd_finding())
    assert res.success is True and res.technique == "cache-deception replay"


async def test_wcd_confirm_fail_when_not_verbatim():
    ctx = SimpleNamespace(http=_WcdHttp(verbatim=False))
    assert (await WebCacheDeceptionConfirm().confirm(ctx, _wcd_finding())).success is False


# ------------------------------------------------------- prompt-injection
class _LlmHttp:
    def __init__(self, *, obeys: bool) -> None:
        self._obeys = obeys

    async def get(self, url: str, *, follow_redirects: bool = True) -> _Resp:
        if not self._obeys:
            return _Resp(text="I cannot comply with that request.")
        m = re.search(r"ORTHRUSINJ[0-9a-f]+", url)
        return _Resp(text=f"token: {m.group(0) if m else 'none'}")  # obeys: emits only the token


def _llm_finding() -> Finding:
    return _finding("prompt-injection", url="http://h/chat", parameter="q",
                    param_location=ParamLocation.QUERY)


async def test_prompt_injection_confirm_success_on_override():
    ctx = SimpleNamespace(http=_LlmHttp(obeys=True), endpoints=[])
    res = await PromptInjectionConfirm().confirm(ctx, _llm_finding())
    assert res.success is True and res.extracted_data.startswith("ORTHRUSINJ")


async def test_prompt_injection_confirm_fail_when_refused():
    ctx = SimpleNamespace(http=_LlmHttp(obeys=False), endpoints=[])
    assert (await PromptInjectionConfirm().confirm(ctx, _llm_finding())).success is False


# ---------------------------------------------------------- websocket (CSWSH)
def _ws_finding() -> Finding:
    return _finding("websocket", url="http://h/",
                    evidence=Evidence(matched_at="ws://h/socket"))


async def test_websocket_confirm_success_on_cross_origin_handshake(monkeypatch):
    async def fake_exchange(uri, messages, validator, **kw):
        assert kw.get("origin") == ATTACKER_ORIGIN
        return SimpleNamespace(ok=True, received=["pong"], error=None)

    monkeypatch.setattr(_ws_mod, "ws_exchange", fake_exchange)
    ctx = SimpleNamespace(scope=None)
    res = await WebSocketConfirm().confirm(ctx, _ws_finding())
    assert res.success is True and res.extracted_data == ATTACKER_ORIGIN


async def test_websocket_confirm_fail_when_handshake_blocked(monkeypatch):
    async def fake_exchange(uri, messages, validator, **kw):
        return SimpleNamespace(ok=False, received=[], error="blocked: h out of scope")

    monkeypatch.setattr(_ws_mod, "ws_exchange", fake_exchange)
    ctx = SimpleNamespace(scope=None)
    res = await WebSocketConfirm().confirm(ctx, _ws_finding())
    assert res.success is False
