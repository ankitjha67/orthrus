"""Tests for the pure Subresource-Integrity verdict logic."""

from __future__ import annotations

from orthrus.bounty.weakness import weakness_label
from orthrus.core.schemas import Severity
from orthrus.scanners.sri import find_missing_sri

PAGE = "https://shop.example.com/checkout"


def _kinds(html):
    return {(k, s) for k, _u, s in find_missing_sri(html, PAGE)}


def test_third_party_script_without_integrity_is_flagged_medium():
    html = '<script src="https://cdn.jsdelivr.net/npm/p@1/p.js"></script>'
    found = find_missing_sri(html, PAGE)
    assert found == [("script", "https://cdn.jsdelivr.net/npm/p@1/p.js", Severity.MEDIUM)]


def test_third_party_script_with_integrity_is_clean():
    html = '<script src="https://cdn.jsdelivr.net/p.js" integrity="sha384-abc" crossorigin></script>'
    assert find_missing_sri(html, PAGE) == []


def test_empty_integrity_is_treated_as_missing():
    html = '<script src="https://cdn.other.com/p.js" integrity=""></script>'
    assert find_missing_sri(html, PAGE)


def test_same_registrable_domain_is_not_flagged():
    # first-party asset on a different subdomain is the same trust sphere
    html = '<script src="https://static.example.com/app.js"></script>'
    assert find_missing_sri(html, PAGE) == []


def test_relative_and_absolute_same_origin_ignored():
    html = ('<script src="/js/app.js"></script>'
            '<script src="https://shop.example.com/a.js"></script>')
    assert find_missing_sri(html, PAGE) == []


def test_http_third_party_is_left_to_mixed_content():
    html = '<script src="http://cdn.other.com/p.js"></script>'
    assert find_missing_sri(html, PAGE) == []


def test_protocol_relative_third_party_is_flagged():
    html = '<script src="//cdn.other.com/p.js"></script>'
    found = find_missing_sri(html, PAGE)
    assert found and found[0][0] == "script"


def test_third_party_stylesheet_is_low():
    html = '<link rel="stylesheet" href="https://fonts.other.com/x.css">'
    assert _kinds(html) == {("stylesheet", Severity.LOW)}


def test_preload_counts_but_non_resource_link_is_ignored():
    html = ('<link rel="preload" as="script" href="https://cdn.other.com/x.js">'
            '<link rel="canonical" href="https://cdn.other.com/page">')
    found = find_missing_sri(html, PAGE)
    assert len(found) == 1 and "x.js" in found[0][1]


def test_duplicate_resource_reported_once():
    html = ('<script src="https://cdn.other.com/p.js"></script>'
            '<script src="https://cdn.other.com/p.js"></script>')
    assert len(find_missing_sri(html, PAGE)) == 1


def test_cwe_353_is_mapped_for_submission():
    assert weakness_label("CWE-353") == "Missing Support for Integrity Check (cwe-353)"
