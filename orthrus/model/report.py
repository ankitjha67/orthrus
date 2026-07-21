"""Platform-native reports from a ProgramFinding (PRD §7.6, Phase 3).

Turns a triaged operator-graph finding into a submission-ready Markdown report
shaped for the target platform's form (HackerOne / Bugcrowd / Intigriti /
YesWeHack / Immunefi). Pure and unit-tested; evidence lives in the graph and is
referenced for the operator to attach.
"""

from __future__ import annotations

REPORT_PLATFORMS = ("generic", "hackerone", "bugcrowd", "intigriti", "yeswehack", "immunefi")

_BUGCROWD_PRIORITY = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "P5"}
_IMPACT = {
    "critical": "Full compromise of the affected asset or its data is achievable.",
    "high": "A meaningful breach of confidentiality, integrity, or availability is achievable.",
    "medium": "Limited impact requiring specific conditions or additional steps.",
    "low": "Minor impact / hardening gap.",
    "info": "Informational — no direct security impact.",
}


def _cvss(finding) -> str:
    if finding.cvss_v3_score is not None:
        return f"{finding.cvss_v3_score} ({finding.cvss_v3_vector or 'vector n/a'})"
    return "not scored"


def render_program_finding(finding, *, platform: str = "generic", program_name: str = "") -> str:
    """Render one ProgramFinding as a platform-native Markdown report."""
    platform = (platform or "generic").lower()
    if platform not in REPORT_PLATFORMS:
        platform = "generic"
    sev = (finding.severity or "info").lower()
    prog = f"**Program:** {program_name}  \n" if program_name else ""
    summary = finding.description_md or f"A {finding.vuln_class} issue was identified on the affected asset."
    evidence = ("Attach the recorded request/response, screenshot, or OAST callback for this finding "
                "(evidence is stored in the operator graph and referenced by content hash).")

    head: list[str] = [f"# {finding.title}", ""]
    if platform == "bugcrowd":
        head += [
            prog + f"**Priority:** {_BUGCROWD_PRIORITY.get(sev, 'P3')} ({sev.capitalize()})",
            f"**Bug type:** map to the closest Bugcrowd VRT · CWE {finding.cwe_id or 'n/a'}",
            f"**CVSS:** {_cvss(finding)}",
        ]
        desc, poc, impact, remed = "Description", "Steps to Reproduce", "Impact", "Remediation"
    elif platform == "intigriti":
        head += [
            prog + f"**Severity:** {sev.capitalize()} (CVSS {_cvss(finding)})",
            f"**Type:** {finding.cwe_id or 'n/a'} · {finding.owasp_id or ''}".rstrip(" ·"),
        ]
        desc, poc, impact, remed = "Description", "Proof of concept", "Impact", "Recommendation"
    elif platform == "immunefi":
        head += [
            prog + f"**Severity:** {sev.capitalize()} — CVSS {_cvss(finding)}",
            f"**Vulnerability type:** {finding.cwe_id or 'n/a'}",
        ]
        desc, poc, impact, remed = "Description", "Proof of Concept", "Impact", "Recommendation"
    else:  # generic / hackerone / yeswehack share the standard shape
        head += [
            prog + f"**Weakness:** {finding.cwe_id or 'n/a'}",
            f"**Severity:** {sev.capitalize()} — CVSS {_cvss(finding)}",
            f"**Confidence:** {finding.confidence}",
        ]
        desc, poc, impact, remed = "Summary", "Steps To Reproduce", "Impact", "Remediation"

    parts = [
        *head,
        "", f"## {desc}", summary,
        "", f"## {poc}", evidence,
        "", f"## {impact}", _IMPACT.get(sev, "See summary."),
        "", f"## {remed}", "Apply standard mitigations for this vulnerability class.",
        "", "---",
        f"_ORTHRUS · {finding.vuln_class} · found by {finding.found_by_tool} · "
        f"confidence {finding.confidence}_",
    ]
    return "\n".join(parts) + "\n"


__all__ = ["render_program_finding", "REPORT_PLATFORMS"]
