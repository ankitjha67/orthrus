"""Tests for the deny-by-default scope validator — the core safety control."""

from __future__ import annotations

import pytest

from hydra.core.config import ScopeConfig
from hydra.utils.scope import ScopeValidator, ScopeViolation


def make(**kwargs) -> ScopeValidator:
    return ScopeValidator(ScopeConfig(**kwargs))


def test_exact_domain_allowed_and_others_denied():
    v = make(domains=["api.target.com"], ports=[80, 443])
    assert v.is_allowed("https://api.target.com/users")
    assert not v.is_allowed("https://evil.com/")
    assert not v.is_allowed("https://other.target.com/")


def test_wildcard_matches_subdomains_and_apex():
    v = make(domains=["*.target.com"])
    assert v.is_allowed("https://target.com/")
    assert v.is_allowed("https://a.target.com/")
    assert v.is_allowed("https://a.b.target.com/")
    assert not v.is_allowed("https://nottarget.com/")
    assert not v.is_allowed("https://target.com.evil.com/")


def test_cidr_ip_scope():
    v = make(ip_ranges=["10.0.0.0/24"], ports=[])
    assert v.is_allowed("http://10.0.0.5/")
    assert not v.is_allowed("http://10.0.1.5/")
    assert not v.is_allowed("http://192.168.0.1/")


def test_port_whitelist():
    v = make(domains=["target.com"], ports=[443])
    assert v.is_allowed("https://target.com/")  # 443 default
    assert not v.is_allowed("http://target.com/")  # 80 not allowed
    assert not v.is_allowed("https://target.com:8443/")


def test_port_any_when_empty():
    v = make(domains=["target.com"], ports=[])
    assert v.is_allowed("https://target.com:8443/")


def test_path_exclusion():
    v = make(domains=["target.com"], ports=[], exclude_paths=[r"/admin/delete/.*", r"/payments"])
    assert v.is_allowed("https://target.com/safe")
    assert not v.is_allowed("https://target.com/admin/delete/42")
    assert not v.is_allowed("https://target.com/payments")


def test_block_third_party_default_denies_unknown_host():
    v = make(domains=["target.com"])
    decision = v.check("https://cdn.googleapis.com/lib.js")
    assert decision.allowed is False


def test_third_party_allowed_but_flagged_when_not_blocking():
    v = make(domains=["target.com"], block_third_party=False)
    decision = v.check("https://cdn.example.com/lib.js")
    assert decision.allowed is True
    assert decision.third_party is True


def test_assert_in_scope_raises():
    v = make(domains=["target.com"])
    with pytest.raises(ScopeViolation):
        v.assert_in_scope("https://evil.com/")


def test_auto_from_target_includes_apex_and_wildcard():
    scope = ScopeConfig.auto_from_target("https://app.target.com")
    v = ScopeValidator(scope)
    assert v.is_allowed("https://app.target.com/")
    assert v.is_allowed("https://x.app.target.com/")


def test_filter_in_scope():
    v = make(domains=["target.com"], ports=[])
    urls = ["https://target.com/a", "https://evil.com/b", "https://target.com/c"]
    assert v.filter_in_scope(urls) == ["https://target.com/a", "https://target.com/c"]
