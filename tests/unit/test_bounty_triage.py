"""Bug-bounty priority scoring and queue ordering."""

from __future__ import annotations

from orthrus.bounty.report import select_and_group
from orthrus.bounty.scope_intake import parse_program_scope
from orthrus.bounty.triage import priority_score
from orthrus.core.schemas import Confidence, Finding, Severity


def _f(vt, sev, conf, url="http://h/x", cvss=None):
    return Finding(vuln_type=vt, title=f"{vt} issue", severity=sev, confidence=conf,
                   url=url, cvss_score=cvss)


def test_confirmed_outranks_unproven():
    conf_crit = priority_score(_f("cmdi", Severity.CRITICAL, Confidence.CONFIRMED))
    conf_med = priority_score(_f("sqli", Severity.MEDIUM, Confidence.CONFIRMED))
    tent_high = priority_score(_f("xss", Severity.HIGH, Confidence.TENTATIVE))
    assert conf_crit == 100.0                         # capped at 100
    assert conf_med > tent_high                        # a confirmed medium beats a tentative high
    assert priority_score(_f("hdr", Severity.INFO, Confidence.TENTATIVE)) < 20


def test_cvss_nudge_within_bounds():
    hi = priority_score(_f("sqli", Severity.HIGH, Confidence.FIRM, cvss=9.0))
    lo = priority_score(_f("sqli", Severity.HIGH, Confidence.FIRM, cvss=1.0))
    assert 0 <= lo < hi <= 100


def test_report_ranks_queue_by_priority():
    ps = parse_program_scope("*.example.com\n")
    findings = [
        _f("xss", Severity.HIGH, Confidence.TENTATIVE, "https://a.example.com/1"),
        _f("sqli", Severity.MEDIUM, Confidence.CONFIRMED, "https://a.example.com/2"),
    ]
    rep = select_and_group(findings, ps, min_confidence="tentative")
    assert rep.groups[0].lead.vuln_type == "sqli"   # confirmed medium ranks above tentative high
