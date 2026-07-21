"""Subdomain permutation / mutation generation (altdns-style)."""

from __future__ import annotations

from orthrus.recon.permutation import permutations, sub_labels


def test_sub_labels_extracts_left_labels_only():
    subs = ["api.example.com", "staging.api.example.com", "www.example.com",
            "example.com", "evil.other.com", "*.example.com"]
    assert sub_labels(subs, "example.com") == ["api", "staging", "www"]


def test_sub_labels_is_case_and_dot_insensitive():
    assert sub_labels(["API.Example.com.", "DEV.example.com"], "example.com") == ["api", "dev"]


def test_permutations_generate_dash_concat_and_numeric_variants():
    perms = set(permutations(["api"], "example.com", cap=500))
    assert "api1.example.com" in perms and "api2.example.com" in perms
    assert "dev-api.example.com" in perms and "api-dev.example.com" in perms
    assert "devapi.example.com" in perms and "apidev.example.com" in perms
    assert "api-old.example.com" in perms
    assert all(p.endswith(".example.com") for p in perms)


def test_permutations_are_capped_and_deduped():
    perms = permutations(["api", "staging", "admin", "portal"], "example.com", cap=20)
    assert len(perms) == 20
    assert len(set(perms)) == 20                       # no duplicates


def test_permutations_empty_without_labels():
    assert permutations([], "example.com") == []


def test_permutations_respect_dns_length_limits():
    long_label = "a" * 60
    perms = permutations([long_label], "example.com", cap=50)
    # every generated label stays within the 63-char DNS label limit
    assert all(len(p.split(".", 1)[0]) <= 63 for p in perms)
