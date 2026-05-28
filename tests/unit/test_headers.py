"""Tests for the pure security-header analyzer."""

from __future__ import annotations

from hydra.scanners.headers import analyze_headers


def _titles(findings) -> set[str]:
    return {f.title for f in findings}


def test_empty_https_headers_flag_all_core_protections():
    findings = analyze_headers("https://target.com/", {})
    titles = _titles(findings)
    assert any("Content-Security-Policy" in t for t in titles)
    assert any("clickjacking" in t.lower() for t in titles)
    assert any("Strict-Transport-Security" in t for t in titles)
    assert any("X-Content-Type-Options" in t for t in titles)
    assert any("Referrer-Policy" in t for t in titles)


def test_http_url_does_not_flag_hsts():
    findings = analyze_headers("http://target.com/", {})
    assert not any("Strict-Transport-Security" in t for t in _titles(findings))


def test_well_configured_headers_have_no_core_findings():
    headers = {
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }
    findings = analyze_headers("https://target.com/", headers)
    assert findings == []


def test_csp_frame_ancestors_satisfies_clickjacking():
    headers = {
        "Content-Security-Policy": "frame-ancestors 'none'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }
    titles = _titles(analyze_headers("https://target.com/", headers))
    assert not any("clickjacking" in t.lower() for t in titles)


def test_version_disclosure():
    titles = _titles(analyze_headers("https://target.com/", {"Server": "Apache/2.4.49"}))
    assert any("Version disclosure" in t for t in titles)


def test_weak_hsts_max_age():
    headers = {
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "Strict-Transport-Security": "max-age=600",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }
    assert any("Weak HSTS" in t for t in _titles(analyze_headers("https://target.com/", headers)))
