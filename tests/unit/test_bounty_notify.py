"""Bounty campaign → Slack summary (reuses the notify integration)."""

from __future__ import annotations

from orthrus.bounty.report import select_and_group
from orthrus.bounty.scope_intake import parse_program_scope
from orthrus.core.schemas import Confidence, Finding, Severity
from orthrus.integrations.notify import slack_message


def test_bounty_bugs_build_a_slack_payload():
    ps = parse_program_scope("*.example.com\n")
    findings = [
        Finding(vuln_type="sqli", title="SQL injection", severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED, url="https://api.example.com/1"),
        Finding(vuln_type="xss", title="Reflected XSS", severity=Severity.HIGH,
                confidence=Confidence.FIRM, url="https://api.example.com/2"),
        Finding(vuln_type="cookie", title="Cookie flag", severity=Severity.LOW,
                confidence=Confidence.FIRM, url="https://api.example.com/3"),
    ]
    report = select_and_group(findings, ps, min_confidence="firm")
    leads = [g.lead for g in report.groups]

    payload = slack_message("bounty · acme", "https://example.com", leads, min_severity="high")
    text = payload["text"]
    assert "SQL injection" in text and "Reflected XSS" in text   # the high+ bugs are listed
    assert "CRITICAL" in text
    assert "Cookie flag" not in text                             # below the 'high' threshold
