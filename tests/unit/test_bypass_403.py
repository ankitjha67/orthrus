"""Tests for the 403/401 access-control bypass scanner."""

from __future__ import annotations

import asyncio
import types

import httpx

from orthrus.core.config import ScopeConfig
from orthrus.core.schemas import Endpoint, HttpMethod
from orthrus.scanners.bypass_403 import (
    Bypass403Scanner,
    bypass_succeeded,
    header_bypass_variants,
    path_bypass_variants,
)
from orthrus.utils.scope import ScopeValidator

# --- pure detectors ------------------------------------------------------

def test_path_variants_include_classics_and_skip_original():
    variants = dict(path_bypass_variants("/admin"))
    assert variants["trailing-slash"] == "/admin/"
    assert variants["dot-slash-prefix"] == "/./admin"
    assert variants["double-slash-prefix"] == "//admin"
    assert variants["uppercase"] == "/ADMIN"
    # the original path is never re-issued as a "bypass"
    assert "/admin" not in variants.values()


def test_header_variants_cover_routing_and_ip_spoof():
    labels = {label for label, _ in header_bypass_variants("/admin", "http://t")}
    assert {"x-original-url", "x-rewrite-url", "x-forwarded-for-localhost"} <= labels


def test_bypass_succeeded_true_on_real_flip():
    assert bypass_succeeded(403, "Forbidden", 200, "welcome to the admin panel") is True


def test_bypass_succeeded_false_when_body_matches_deny_page():
    body = "403 Forbidden " * 40
    assert bypass_succeeded(403, body, 200, body) is False


def test_bypass_succeeded_false_on_deny_marker():
    assert bypass_succeeded(403, "x", 200, "You are not authorized to view this") is False


def test_bypass_succeeded_false_when_original_not_a_deny():
    assert bypass_succeeded(200, "a" * 50, 200, "b" * 500) is False


def test_bypass_succeeded_false_when_variant_not_2xx():
    assert bypass_succeeded(403, "a" * 50, 403, "b" * 500) is False


# --- end-to-end scan -----------------------------------------------------

def _resp(text="", status=200):
    return httpx.Response(status, text=text, request=httpx.Request("GET", "http://t/"))


class _FakeHttp:
    """Routes by (url, predicate) so header- and path-based bypasses are testable."""

    def __init__(self, handler):
        self._handler = handler

    async def request(self, method, url, headers=None, follow_redirects=True, **kwargs):
        return self._handler(url, headers or {})


def _ctx(handler, endpoints):
    return types.SimpleNamespace(
        config=types.SimpleNamespace(target="http://t/"),
        scope=ScopeValidator(ScopeConfig(domains=["t"], ports=[])),
        http=_FakeHttp(handler),
        endpoints=endpoints,
    )


def _scan(ctx):
    async def run():
        return [f async for f in Bypass403Scanner().scan(ctx)]

    return asyncio.run(run())


def test_path_bypass_is_detected():
    def handler(url, headers):
        if url == "http://t/admin":
            return _resp("403 Forbidden", 403)
        if url == "http://t/admin/":
            return _resp("<h1>Admin dashboard</h1> full control here", 200)
        return _resp("not found", 404)

    eps = [Endpoint(url="http://t/admin", method=HttpMethod.GET, response_status=403)]
    findings = _scan(_ctx(handler, eps))
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "access-control"
    assert "path" in f.title
    assert f.confidence.value == "firm"


def test_header_bypass_is_detected():
    def handler(url, headers):
        if url != "http://t/admin":
            return _resp("not found", 404)
        # every path mutation of /admin also 404s here (only the exact URL exists),
        # so the only way through is the X-Original-URL routing header.
        if "X-Original-URL" in headers:
            return _resp("<h1>Admin dashboard</h1> internal only", 200)
        return _resp("403 Forbidden", 403)

    eps = [Endpoint(url="http://t/admin", method=HttpMethod.GET, response_status=403)]
    findings = _scan(_ctx(handler, eps))
    assert len(findings) == 1
    assert "header" in findings[0].title


def test_no_finding_when_deny_is_consistent():
    def handler(url, headers):
        # Everything is 403 or a soft-403 200 that still says "forbidden".
        if url == "http://t/admin":
            return _resp("403 Forbidden", 403)
        return _resp("Access denied", 200)

    eps = [Endpoint(url="http://t/admin", method=HttpMethod.GET, response_status=403)]
    assert _scan(_ctx(handler, eps)) == []
