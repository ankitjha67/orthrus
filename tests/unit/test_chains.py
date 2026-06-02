"""Attack-path chaining: correlation, distinct-finding + same-host rules."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.chains import build_chain_report, correlate_findings


def F(vuln_type, url):
    return SimpleNamespace(vuln_type=vuln_type, url=url)


def _names(chains):
    return {c.name for c in chains}


def test_ssrf_plus_exposed_service_chains_to_critical():
    chains = correlate_findings([
        F("ssrf", "https://app.test/fetch"),
        F("exposed-service", "https://app.test/redis"),
    ])
    assert len(chains) == 1
    c = chains[0]
    assert c.severity == "critical" and "internal-service" in c.name
    assert [s.vuln_type for s in c.steps] == ["ssrf", "exposed-service"]
    assert c.host == "app.test"


def test_single_finding_yields_no_chain():
    assert correlate_findings([F("ssrf", "https://app.test/x")]) == []


def test_distinct_findings_required_per_link():
    # Two SSRFs cannot satisfy a chain that also needs an exposed service.
    assert correlate_findings([
        F("ssrf", "https://app.test/a"), F("ssrf", "https://app.test/b"),
    ]) == []


def test_same_host_required():
    # SSRF and the exposed service on different hosts must NOT chain.
    chains = correlate_findings([
        F("ssrf", "https://a.test/fetch"),
        F("exposed-service", "https://b.test/redis"),
    ])
    assert chains == []


def test_session_to_privesc_chain():
    chains = correlate_findings([
        F("jwt", "https://app.test/login"),
        F("idor", "https://app.test/order/1"),
    ])
    assert "Session foothold → privilege escalation" in _names(chains)


def test_multiple_chains_sorted_critical_first():
    findings = [
        F("xss", "https://app.test/q"),            # } XSS → ATO (high)
        F("csrf", "https://app.test/form"),        # }
        F("exposed-secret", "https://app.test/.env"),  # } leaked secret → auth forgery (critical)
        F("jwt", "https://app.test/login"),            # }  (also session→privesc)
    ]
    chains = correlate_findings(findings)
    assert chains[0].severity == "critical"   # critical sorts ahead of high
    assert "XSS → account takeover" in _names(chains)
    assert "Leaked secret → authentication forgery" in _names(chains)


def test_report_summary_counts_critical():
    report = build_chain_report([
        F("ssrf", "https://app.test/fetch"),
        F("exposed-service", "https://app.test/redis"),
    ])
    assert "1 attack path(s)" in report.summary() and "1 critical" in report.summary()


def test_unrelated_findings_no_chain():
    chains = correlate_findings([
        F("security-headers", "https://app.test/"),
        F("tls", "https://app.test/"),
    ])
    assert chains == []
