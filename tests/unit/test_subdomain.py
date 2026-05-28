"""Tests for crt.sh parsing."""

from __future__ import annotations

from hydra.recon.subdomain_enum import parse_crtsh


def test_parse_crtsh_extracts_in_domain_subs():
    entries = [
        {"name_value": "api.target.com\nwww.target.com"},
        {"name_value": "*.staging.target.com"},
        {"name_value": "target.com"},
        {"name_value": "other.example.org"},  # out of domain -> ignored
    ]
    subs = parse_crtsh(entries, "target.com")
    assert "api.target.com" in subs
    assert "www.target.com" in subs
    assert "staging.target.com" in subs  # wildcard stripped
    assert "target.com" in subs
    assert "other.example.org" not in subs


def test_parse_crtsh_empty():
    assert parse_crtsh([], "target.com") == set()
