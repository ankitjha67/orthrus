"""Tests for the pure TLS verdict logic."""

from __future__ import annotations

from hydra.core.schemas import Severity
from hydra.scanners.tls_analyzer import classify_tls


def _titles(issues) -> set[str]:
    return {t for _s, t, _d, _c in issues}


def test_clean_modern_config_has_no_issues():
    facts = {
        "sslv2": False,
        "sslv3": False,
        "tls1_0": False,
        "tls1_1": False,
        "self_signed": False,
        "hostname_mismatch": False,
        "expired": False,
        "weak_ciphers": [],
    }
    assert classify_tls(facts) == []


def test_legacy_protocols_flagged():
    titles = _titles(classify_tls({"sslv3": True, "tls1_0": True}))
    assert any("SSL 3.0" in t for t in titles)
    assert any("TLS 1.0" in t for t in titles)


def test_expired_is_high():
    issues = classify_tls({"expired": True})
    assert any(s == Severity.HIGH and "expired" in t.lower() for s, t, _d, _c in issues)


def test_self_signed_and_weak_ciphers():
    issues = classify_tls({"self_signed": True, "weak_ciphers": ["TLS_RSA_WITH_RC4_128_SHA"]})
    titles = _titles(issues)
    assert any("Self-signed" in t for t in titles)
    assert any("Weak cipher" in t for t in titles)
