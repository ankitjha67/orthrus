"""Tests for race-condition + auth (entropy / default-creds) pure helpers."""

from __future__ import annotations

from hydra.scanners.auth import is_session_cookie, shannon_entropy, token_strength_bits
from hydra.scanners.default_creds import find_login_fields, looks_like_success
from hydra.scanners.race_condition import race_signal


def test_race_signal_partial_success():
    assert race_signal(3, 8) is True       # contention
    assert race_signal(1, 8) is False      # locked (single success)
    assert race_signal(8, 8) is False      # idempotent (all succeed)
    assert race_signal(0, 8) is False


def test_shannon_entropy_and_strength():
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("ab") == 1.0
    weak = token_strength_bits("abc123")          # ~15 bits
    strong = token_strength_bits("a1b2c3d4" * 8)  # long
    assert weak < 64 < strong


def test_is_session_cookie():
    assert is_session_cookie("sessionid") is True
    assert is_session_cookie("auth_token") is True
    assert is_session_cookie("theme") is False


def test_find_login_fields():
    assert find_login_fields(["username", "password"]) == ("username", "password")
    assert find_login_fields(["email", "pwd", "csrf"]) == ("email", "pwd")
    assert find_login_fields(["q"]) == (None, None)


def test_looks_like_success_redirect():
    # baseline = 200 invalid; attempt = 302 -> success
    assert looks_like_success(200, "Invalid credentials", 302, "") is True


def test_looks_like_success_error_cleared():
    assert looks_like_success(200, "Invalid credentials", 200, "Welcome admin") is True


def test_looks_like_failure():
    assert looks_like_success(200, "Invalid credentials", 200, "Invalid credentials") is False
