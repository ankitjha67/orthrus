"""Tests for cache-poisoning reflection and cacheability checks."""

from __future__ import annotations

from orthrus.scanners.cache_poisoning import MARKER, is_cacheable, reflects_marker


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
