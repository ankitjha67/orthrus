"""Tests for content-discovery classification helpers."""

from __future__ import annotations

from orthrus.recon.content_discovery import is_interesting, is_sensitive


def test_200_is_interesting_when_unlike_baseline():
    # baseline soft-404 is 200 with length 500; a real page differs a lot.
    assert is_interesting(200, 5000, 200, 500) is True


def test_soft_404_match_is_not_interesting():
    assert is_interesting(200, 505, 200, 500) is False  # within 5% of baseline


def test_403_and_401_are_interesting():
    assert is_interesting(403, 100, 404, 200) is True
    assert is_interesting(401, 100, 404, 200) is True


def test_404_is_not_interesting():
    assert is_interesting(404, 100, 404, 200) is False


def test_sensitive_paths():
    assert is_sensitive(".env") is True
    assert is_sensitive(".git/HEAD") is True
    assert is_sensitive("admin") is False
