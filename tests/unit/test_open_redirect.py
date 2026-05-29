"""Tests for the open-redirect Location detector."""

from __future__ import annotations

from orthrus.scanners.open_redirect import ATTACKER_HOST, is_open_redirect


def test_absolute_attacker_url():
    assert is_open_redirect(f"https://{ATTACKER_HOST}/") is True


def test_protocol_relative():
    assert is_open_redirect(f"//{ATTACKER_HOST}/path") is True


def test_backslash_bypass_normalized():
    assert is_open_redirect(f"https:/\\{ATTACKER_HOST}/") is True


def test_subdomain_of_attacker():
    assert is_open_redirect(f"https://evil.{ATTACKER_HOST}/") is True


def test_local_path_is_safe():
    assert is_open_redirect("/account/dashboard") is False


def test_other_host_is_safe():
    assert is_open_redirect("https://legitimate.example/") is False


def test_none_location():
    assert is_open_redirect(None) is False
