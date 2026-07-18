"""Machine-readable campaign export (findings.json)."""

from __future__ import annotations

import json

from orthrus.bounty.campaign import write_reports
from orthrus.bounty.report import campaign_summary, select_and_group
from orthrus.bounty.scope_intake import parse_program_scope
from orthrus.core.schemas import Confidence, Finding, Severity


def _f(vt, sev, conf, url, title, **kw):
    return Finding(vuln_type=vt, title=title, severity=sev, confidence=conf, url=url, **kw)


def _report():
    ps = parse_program_scope("*.example.com\n")
    findings = [
        _f("sqli", Severity.CRITICAL, Confidence.CONFIRMED, "https://api.example.com/i?id=1",
           "SQL injection", cwe="CWE-89", cvss_score=9.8),
        _f("xss", Severity.MEDIUM, Confidence.FIRM, "https://api.example.com/s?q=1", "Reflected XSS"),
    ]
    return select_and_group(findings, ps, min_confidence="firm"), findings


def test_summary_ranks_and_carries_metadata():
    report, findings = _report()
    summ = campaign_summary(report, "ExampleCorp", prior_seen={id(report.groups[0].lead): 3})
    assert summ["program"] == "ExampleCorp"
    assert summ["reportable"] == 2
    assert summ["severity_counts"] == {"critical": 1, "medium": 1}
    # ranked: the confirmed critical outranks the firm medium
    top = summ["bugs"][0]
    assert top["rank"] == 1 and top["severity"] == "critical" and top["vuln_type"] == "sqli"
    assert top["cwe"] == "CWE-89" and top["cvss"] == 9.8
    assert top["prior_seen"] == 3
    assert summ["bugs"][1]["severity"] == "medium"


def test_write_reports_emits_findings_json(tmp_path):
    report, _ = _report()
    written = write_reports(report, tmp_path, program_name="ExampleCorp")
    assert "findings.json" in written
    data = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert data["reportable"] == 2
    assert [b["rank"] for b in data["bugs"]] == [1, 2]
    assert data["bugs"][0]["host"] == "api.example.com"
