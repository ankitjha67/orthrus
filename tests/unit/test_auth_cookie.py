"""Tests for cookie security-attribute analysis."""

from __future__ import annotations

from orthrus.core.schemas import Severity
from orthrus.scanners.auth import cookie_issues


def _titles(issues) -> set[str]:
    return {title for _name, _sev, title, _cwe in issues}


def test_bare_cookie_over_https_flags_all_three():
    issues = cookie_issues("sid=abc123", is_https=True)
    titles = _titles(issues)
    assert any("Secure" in t for t in titles)
    assert any("HttpOnly" in t for t in titles)
    assert any("SameSite" in t for t in titles)


def test_http_does_not_flag_secure():
    titles = _titles(cookie_issues("sid=abc123", is_https=False))
    assert not any("Secure" in t for t in titles)


def test_fully_protected_cookie_is_clean():
    assert cookie_issues("sid=abc; Secure; HttpOnly; SameSite=Lax", is_https=True) == []


def test_cookie_name_extracted():
    issues = cookie_issues("session_id=xyz; HttpOnly", is_https=True)
    assert all(name == "session_id" for name, *_ in issues)
    # Secure missing -> Medium present; HttpOnly present -> not flagged
    assert any(sev == Severity.MEDIUM for _n, sev, _t, _c in issues)
