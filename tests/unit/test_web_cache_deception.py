"""Web cache deception scanner."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Severity
from orthrus.scanners.web_cache_deception import (
    WebCacheDeceptionScanner,
    deception_signal,
    looks_static,
)


def test_looks_static() -> None:
    assert looks_static("/app/main.css") is True
    assert looks_static("/logo.PNG") is True
    assert looks_static("/account") is False


def test_deception_signal_requires_verbatim_200() -> None:
    assert deception_signal(200, "SECRET BALANCE", 200, "SECRET BALANCE") is True
    assert deception_signal(200, "SECRET", 404, "not found") is False  # static path 404'd (safe)
    assert deception_signal(200, "page A", 200, "different page B") is False
    assert deception_signal(200, "", 200, "") is False


class FakeResp:
    def __init__(self, status_code: int, text: str, headers: dict[str, str] | None = None) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


def _ctx(http: object, endpoints: list[str]) -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(target="http://h/"),
        endpoints=[SimpleNamespace(url=u) for u in endpoints],
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        http=http,
    )


class DeceptiveHttp:
    """Returns the account page verbatim for /account and any /account/* path."""

    async def get(self, url: str, **kw: object) -> FakeResp:
        if "/account" in url:
            return FakeResp(200, "<html>balance=$4200</html>", {"X-Cache": "MISS"})
        return FakeResp(404, "not found")


class SafeHttp:
    """Static sub-paths correctly 404 -> no deception."""

    async def get(self, url: str, **kw: object) -> FakeResp:
        if url.rstrip("/").endswith("/account"):
            return FakeResp(200, "<html>balance=$4200</html>")
        return FakeResp(404, "not found")


async def test_scanner_flags_deception() -> None:
    findings = [f async for f in WebCacheDeceptionScanner().scan(_ctx(DeceptiveHttp(), ["http://h/account"]))]
    wcd = [f for f in findings if f.vuln_type == "web-cache-deception"]
    assert len(wcd) == 1
    assert wcd[0].severity == Severity.MEDIUM  # cacheable (X-Cache header)
    assert wcd[0].cwe == "CWE-525"


async def test_scanner_safe_when_subpath_404s() -> None:
    findings = [f async for f in WebCacheDeceptionScanner().scan(_ctx(SafeHttp(), ["http://h/account"]))]
    assert [f for f in findings if f.vuln_type == "web-cache-deception"] == []
