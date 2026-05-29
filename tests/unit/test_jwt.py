"""Tests for JWT discovery and analysis."""

from __future__ import annotations

import time

import jwt

from orthrus.core.schemas import Severity
from orthrus.scanners.jwt_analyzer import analyze_jwt, find_jwts


def _titles(issues) -> str:
    return " | ".join(t for _s, t, _d, _c in issues)


def test_find_jwts_in_text():
    token = jwt.encode({"user": "x"}, "k", algorithm="HS256")
    found = find_jwts(f"Authorization: Bearer {token}; other=1")
    assert token in found


def test_weak_secret_detected():
    token = jwt.encode({"user": "admin", "exp": int(time.time()) + 3600}, "secret", algorithm="HS256")
    issues = analyze_jwt(token)
    assert any(s == Severity.HIGH and "weak" in t.lower() for s, t, _d, _c in issues)


def test_strong_secret_not_flagged_weak():
    token = jwt.encode(
        {"user": "admin", "exp": int(time.time()) + 3600},
        "a-very-long-random-key-not-in-any-wordlist-9f8e7d",
        algorithm="HS256",
    )
    issues = analyze_jwt(token)
    assert not any("weak" in t.lower() for _s, t, _d, _c in issues)


def test_alg_none_detected():
    token = jwt.encode({"user": "x", "exp": int(time.time()) + 3600}, "", algorithm="none")
    issues = analyze_jwt(token)
    assert any("none" in t.lower() for _s, t, _d, _c in issues)


def test_missing_exp_detected():
    token = jwt.encode({"user": "x"}, "longsecretkey-not-in-wordlist-1234", algorithm="HS256")
    assert any("expiration" in t.lower() for _s, t, _d, _c in analyze_jwt(token))


def test_sensitive_claim_detected():
    token = jwt.encode(
        {"user": "x", "password": "p", "exp": int(time.time()) + 3600},
        "longsecretkey-not-in-wordlist-1234",
        algorithm="HS256",
    )
    assert any("sensitive" in t.lower() for _s, t, _d, _c in analyze_jwt(token))
