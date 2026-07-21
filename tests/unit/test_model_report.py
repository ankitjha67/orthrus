"""Platform-native ProgramFinding report renderer (PRD §7.6)."""

from __future__ import annotations

from orthrus.model.report import REPORT_PLATFORMS, render_program_finding


class _Finding:
    title = "SQL injection in /search"
    severity = "critical"
    confidence = "confirmed"
    vuln_class = "sqli.error"
    cwe_id = "CWE-89"
    owasp_id = None
    cvss_v3_score = 9.8
    cvss_v3_vector = "CVSS:3.1/AV:N/AC:L"
    cvss_v4_score = None
    description_md = "The id parameter is injectable."
    found_by_tool = "dalfox"
    signature = "sqli.error|api.acme.com|SQL injection"


def test_generic_and_hackerone_shape():
    md = render_program_finding(_Finding(), platform="hackerone", program_name="Acme")
    assert md.startswith("# SQL injection in /search")
    assert "**Program:** Acme" in md
    assert "CWE-89" in md and "CVSS 9.8" in md
    assert "## Summary" in md and "## Steps To Reproduce" in md and "## Remediation" in md
    assert "found by dalfox" in md


def test_bugcrowd_uses_priority_rating():
    md = render_program_finding(_Finding(), platform="bugcrowd")
    assert "**Priority:** P1 (Critical)" in md and "VRT" in md


def test_intigriti_and_immunefi_headings():
    intg = render_program_finding(_Finding(), platform="intigriti")
    assert "## Recommendation" in intg and "## Proof of concept" in intg
    imm = render_program_finding(_Finding(), platform="immunefi")
    assert "Vulnerability type" in imm


def test_unknown_platform_falls_back_to_generic():
    md = render_program_finding(_Finding(), platform="bogus")
    assert "## Summary" in md   # generic shape


def test_all_declared_platforms_render():
    for p in REPORT_PLATFORMS:
        assert render_program_finding(_Finding(), platform=p).startswith("# ")
