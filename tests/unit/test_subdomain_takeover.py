"""Subdomain takeover scanner."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Severity
from orthrus.scanners.subdomain_takeover import (
    SubdomainTakeoverScanner,
    match_takeover_fingerprint,
)


def test_match_fingerprints() -> None:
    assert match_takeover_fingerprint("There isn't a GitHub Pages site here.") == "GitHub Pages"
    assert match_takeover_fingerprint("<Error><Code>NoSuchBucket</Code></Error>") == "AWS S3"
    assert match_takeover_fingerprint("Fastly error: unknown domain foo.com") == "Fastly"
    assert match_takeover_fingerprint("Welcome to my normal homepage") is None


def test_generic_404_pages_do_not_false_positive() -> None:
    # Regression: a plain 404 (WebLogic, nginx, Apache default) must NOT match.
    assert match_takeover_fingerprint("<html><title>404 Not Found</title></html>") is None
    assert match_takeover_fingerprint("The requested URL was not found on this server.") is None
    assert match_takeover_fingerprint("404 - Web Site not found") is None
    assert match_takeover_fingerprint("Error 404--Not Found (WebLogic)") is None


class FakeResp:
    def __init__(self, text: str) -> None:
        self.text = text


def _ctx(http: object, endpoints: list[str]) -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(target="http://h/"),
        endpoints=[SimpleNamespace(url=u) for u in endpoints],
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        http=http,
    )


class DanglingHttp:
    async def get(self, url: str, **kw: object) -> FakeResp:
        return FakeResp("There isn't a GitHub Pages site here.")


class NormalHttp:
    async def get(self, url: str, **kw: object) -> FakeResp:
        return FakeResp("<html>welcome to the app</html>")


async def test_scanner_flags_takeover() -> None:
    findings = [f async for f in SubdomainTakeoverScanner().scan(_ctx(DanglingHttp(), []))]
    st = [f for f in findings if f.vuln_type == "subdomain-takeover"]
    assert len(st) == 1
    assert st[0].severity == Severity.HIGH
    assert "GitHub Pages" in st[0].title


async def test_scanner_quiet_on_normal_host() -> None:
    findings = [f async for f in SubdomainTakeoverScanner().scan(_ctx(NormalHttp(), []))]
    assert [f for f in findings if f.vuln_type == "subdomain-takeover"] == []


async def test_scanner_dedupes_per_host() -> None:
    ctx = _ctx(DanglingHttp(), ["http://h/a", "http://h/b"])
    findings = [f async for f in SubdomainTakeoverScanner().scan(ctx)]
    assert len([f for f in findings if f.vuln_type == "subdomain-takeover"]) == 1
