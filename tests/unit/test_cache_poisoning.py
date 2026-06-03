"""Tests for cache-poisoning reflection and cacheability checks."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.scanners.cache_poisoning import (
    MARKER,
    CachePoisoningScanner,
    is_cacheable,
    reflects_marker,
)


def test_marker_in_body():
    assert reflects_marker(f'<link href="https://{MARKER}/a.css">', {}) is True


def test_marker_in_header():
    assert reflects_marker("clean body", {"Location": f"https://{MARKER}/"}) is True


def test_no_reflection():
    assert reflects_marker("clean body", {"Content-Type": "text/html"}) is False


def test_cacheable_via_indicator_header():
    assert is_cacheable({"X-Cache": "HIT", "Age": "42"}) is True


def test_cacheable_via_cache_control():
    assert is_cacheable({"Cache-Control": "public, max-age=3600"}) is True


def test_not_cacheable():
    assert is_cacheable({"Cache-Control": "no-store"}) is False


# ----------------------------------------------- active poisoning confirmation
class _Resp:
    def __init__(self, text: str) -> None:
        self.text = text
        self.headers = {"Cache-Control": "public, max-age=60", "Age": "0"}


class _CachingHttp:
    """Reflects X-Forwarded-Host; the vulnerable variant caches per-URL + serves it."""

    def __init__(self, vulnerable: bool) -> None:
        self.vulnerable = vulnerable
        self.cache: dict[str, _Resp] = {}

    async def get(self, url, headers=None, follow_redirects=False):  # noqa: ANN001
        if self.vulnerable and url in self.cache:
            return self.cache[url]  # serve the stored (possibly poisoned) response
        xfh = (headers or {}).get("X-Forwarded-Host", "")
        resp = _Resp(f"<html>canonical host: {xfh}</html>")
        if self.vulnerable:
            self.cache[url] = resp
        return resp


def _ctx(http: object) -> SimpleNamespace:
    return SimpleNamespace(
        endpoints=[],
        http=http,
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(target="http://shop.test/"),
    )


async def test_confirmed_poisoning_when_cache_serves_clean_request():
    findings = [f async for f in CachePoisoningScanner().scan(_ctx(_CachingHttp(vulnerable=True)))]
    confirmed = [f for f in findings if "Confirmed" in f.title]
    assert len(confirmed) == 1
    assert str(confirmed[0].severity) == "high"
    assert str(confirmed[0].confidence) == "confirmed"


async def test_only_candidate_when_clean_request_not_poisoned():
    # Reflects + cacheable headers, but the clean re-fetch is not served from cache,
    # so it stays a candidate (no confirmed poisoning, no false escalation).
    findings = [f async for f in CachePoisoningScanner().scan(_ctx(_CachingHttp(vulnerable=False)))]
    assert not any("Confirmed" in f.title for f in findings)
    assert any("candidate" in f.title for f in findings)
