"""Bug-bounty module: scope intake (in/out-of-scope) and submission reporting."""

from __future__ import annotations

from orthrus.bounty.report import render_index, render_submission, select_and_group
from orthrus.bounty.scope_intake import parse_program_scope
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity

# --------------------------------------------------------------- scope intake

SCOPE_TEXT = """
# example program
*.example.com
api.example.com
https://app.example.com/login
10.0.0.0/24
!admin.example.com
!*.internal.example.com
"""


def test_parse_scope_in_and_out():
    ps = parse_program_scope(SCOPE_TEXT)
    assert "example.com" in ps.domains and "api.example.com" in ps.domains
    assert "10.0.0.0/24" in ps.ip_ranges
    # seeds: apex for the wildcard, the explicit host, and the explicit URL
    assert "https://example.com" in ps.seeds
    assert "https://app.example.com/login" in ps.seeds
    assert any("admin.example.com" in o for o in ps.out_of_scope)


def test_in_scope_and_exclusions():
    ps = parse_program_scope(SCOPE_TEXT)
    assert ps.is_in_scope("www.example.com") is True       # subdomain of *.example.com
    assert ps.is_in_scope("api.example.com") is True
    assert ps.is_in_scope("admin.example.com") is False     # excluded
    assert ps.is_in_scope("x.internal.example.com") is False  # excluded wildcard
    assert ps.is_in_scope("evil.com") is False              # not in scope
    assert ps.is_in_scope("10.0.0.5") is True               # inside the CIDR


def test_ip_url_routes_to_ip_ranges_not_domains():
    ps = parse_program_scope("http://127.0.0.1:8791\n")
    assert ps.ip_ranges == ["127.0.0.1/32"]
    assert ps.domains == []                                  # an IP must not land in domains
    assert ps.seeds == ["http://127.0.0.1:8791"]
    assert ps.is_in_scope("127.0.0.1") is True


def test_empty_scope_has_no_domains():
    ps = parse_program_scope("# just a comment\n\n")
    assert ps.domains == [] and ps.ip_ranges == []


# --------------------------------------------------------------- reporting

def _f(vt, sev, conf, url, **kw):
    base = dict(vuln_type=vt, title=kw.pop("title", f"{vt} issue"), severity=sev,
                confidence=conf, url=url)
    base.update(kw)
    return Finding(**base)


def test_report_filters_out_of_scope_and_low_confidence():
    ps = parse_program_scope("*.example.com\n")
    findings = [
        _f("sqli", Severity.HIGH, Confidence.CONFIRMED, "https://api.example.com/x?id=1",
           title="SQL injection", parameter="id"),
        _f("xss", Severity.MEDIUM, Confidence.TENTATIVE, "https://api.example.com/s?q=1"),  # below floor
        _f("sqli", Severity.HIGH, Confidence.CONFIRMED, "https://evil.com/x"),              # out of scope
    ]
    report = select_and_group(findings, ps, min_confidence="firm")
    assert report.reportable == 1
    assert report.out_of_scope == 1
    assert report.below_confidence == 1
    assert report.groups[0].lead.vuln_type == "sqli"


def test_report_dedupes_same_bug_across_params():
    ps = parse_program_scope("*.example.com\n")
    findings = [
        _f("xss", Severity.HIGH, Confidence.FIRM, "https://a.example.com/p?x=1",
           title="Reflected XSS via x", parameter="x"),
        _f("xss", Severity.HIGH, Confidence.FIRM, "https://a.example.com/p?y=1",
           title="Reflected XSS via y", parameter="y"),
    ]
    report = select_and_group(findings, ps, min_confidence="firm")
    assert report.reportable == 1                       # collapsed to one bug
    assert len(report.groups[0].instances) == 2


def test_render_submission_has_repro_and_sections():
    ps = parse_program_scope("*.example.com\n")
    f = _f("sqli", Severity.CRITICAL, Confidence.CONFIRMED,
           "https://api.example.com/item?id=1", title="SQL injection", parameter="id",
           cwe="CWE-89", cvss_score=9.8,
           evidence=Evidence(request_raw="GET /item?id=1 HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
                             matched_at="SQL syntax error"))
    report = select_and_group([f], ps, min_confidence="firm", techniques={f.id: "error-based replay"})
    md = render_submission(report.groups[0], program_name="ExampleCorp")
    assert "## Steps to Reproduce" in md and "## Impact" in md and "## Remediation" in md
    assert "curl -sk" in md                              # reproduction snippet embedded
    assert "CVSS 9.8" in md and "CWE-89" in md
    assert "error-based replay" in md                    # confirmation technique surfaced
    idx = render_index(report, "ExampleCorp")
    assert "1 reportable bug" in idx and "api.example.com" in idx


def test_prior_seen_flag_renders_in_report_and_index():
    ps = parse_program_scope("*.example.com\n")
    f = _f("sqli", Severity.HIGH, Confidence.FIRM, "https://api.example.com/item?id=1",
           title="SQL injection", parameter="id")
    report = select_and_group([f], ps, min_confidence="firm")
    lead = report.groups[0].lead

    # not seen before -> no duplicate callout / marker
    assert "Seen before" not in render_submission(report.groups[0])
    assert "♻" not in render_index(report)

    # seen in 2 earlier runs -> callout in the bug report + marker/footnote in the index
    md = render_submission(report.groups[0], prior_seen=2)
    assert "Seen before" in md and "2 earlier runs" in md
    idx = render_index(report, prior_seen={id(lead): 2})
    assert "♻" in idx and "possible duplicate" in idx
