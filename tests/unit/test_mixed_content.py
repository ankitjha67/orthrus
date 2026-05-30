"""Mixed-content / insecure-transport reference scanner."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Severity
from orthrus.scanners.mixed_content import MixedContentScanner, find_mixed_content


# ----------------------------------------------------------------- detector
def test_form_action_over_http_is_high():
    html = '<form action="http://insecure.example/login" method="post">'
    out = find_mixed_content(html, "https://h/login")
    assert out == [("form-action", "http://insecure.example/login", Severity.HIGH)]


def test_http_script_is_medium():
    html = '<script src="http://cdn.example/a.js"></script>'
    out = find_mixed_content(html, "https://h/")
    assert ("resource", "http://cdn.example/a.js", Severity.MEDIUM) in out


def test_https_and_relative_refs_ignored():
    html = '<script src="https://ok/a.js"></script><img src="/local.png">'
    assert find_mixed_content(html, "https://h/") == []


def test_non_https_page_never_flags():
    html = '<form action="http://x/login">'
    assert find_mixed_content(html, "http://h/login") == []


def test_dedup_same_url():
    html = '<img src="http://x/a.png"><img src="http://x/a.png">'
    assert len(find_mixed_content(html, "https://h/")) == 1


# ----------------------------------------------------------------- scan flow
class _Resp:
    def __init__(self, text: str, url: str) -> None:
        self.text = text
        self.url = url
        self.headers = {"content-type": "text/html"}


class _Http:
    def __init__(self, text: str, url: str) -> None:
        self._resp = _Resp(text, url)

    async def get(self, url: str, **kw: object) -> _Resp:
        return self._resp


def _ctx(text: str, target: str) -> SimpleNamespace:
    return SimpleNamespace(
        endpoints=[],
        http=_Http(text, target),
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(target=target),
    )


async def test_scan_flags_insecure_form_action():
    html = '<html><form action="http://insecure/login" method="post">u</form></html>'
    findings = [f async for f in MixedContentScanner().scan(_ctx(html, "https://h/login"))]
    assert len(findings) == 1
    assert findings[0].vuln_type == "mixed-content"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].cwe == "CWE-319"


async def test_scan_quiet_on_clean_https_page():
    html = '<html><script src="https://ok/a.js"></script></html>'
    assert [f async for f in MixedContentScanner().scan(_ctx(html, "https://h/"))] == []
