"""Report assembly (PRD §8): JSON, CSV, HTML (Jinja2), and PDF (Chromium).

Builds a single report context from stored findings — CVSS-scored, OWASP-mapped,
with confirmation evidence and base64-embedded screenshots — then renders it to
the requested format. The executive/technical/compliance HTML templates live in
``reporting/templates``.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
from datetime import datetime
from typing import Any

import aiofiles

from orthrus import __version__
from orthrus.core.config import get_settings
from orthrus.db.models import Exploitation as ExploitationRow
from orthrus.db.models import Finding as FindingRow
from orthrus.db.store import Store
from orthrus.intel.cve_intel import epss_for_text
from orthrus.reporting.attack_map import attack_for, build_navigator_layer, d3fend_for
from orthrus.reporting.cvss import DEFAULT_VECTORS, base_score, v4_for
from orthrus.utils import crypto
from orthrus.utils.logger import get_logger

logger = get_logger("reporting")

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
VALID_TEMPLATES = {"executive", "technical", "compliance"}
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

OWASP_2021 = {
    "sqli": "A03:2021 - Injection",
    "cmd-injection": "A03:2021 - Injection",
    "ssti": "A03:2021 - Injection",
    "xss": "A03:2021 - Injection",
    "lfi": "A03:2021 - Injection",
    "xxe": "A05:2021 - Security Misconfiguration",
    "ssrf": "A10:2021 - Server-Side Request Forgery",
    "idor": "A01:2021 - Broken Access Control",
    "csrf": "A01:2021 - Broken Access Control",
    "open-redirect": "A01:2021 - Broken Access Control",
    "cors": "A05:2021 - Security Misconfiguration",
    "security-headers": "A05:2021 - Security Misconfiguration",
    "cache-poisoning": "A05:2021 - Security Misconfiguration",
    "graphql": "A05:2021 - Security Misconfiguration",
    "graphql-dos": "A05:2021 - Security Misconfiguration",
    "exposed-file": "A05:2021 - Security Misconfiguration",
    "websocket": "A05:2021 - Security Misconfiguration",
    "auth-session": "A07:2021 - Identification and Authentication Failures",
    "jwt": "A07:2021 - Identification and Authentication Failures",
    "deserialization": "A08:2021 - Software and Data Integrity Failures",
    "dependency-confusion": "A08:2021 - Software and Data Integrity Failures",
    "prototype-pollution": "A08:2021 - Software and Data Integrity Failures",
    "tls": "A02:2021 - Cryptographic Failures",
    "cve": "A06:2021 - Vulnerable and Outdated Components",
    "default-creds": "A07:2021 - Identification and Authentication Failures",
    "race-condition": "A04:2021 - Insecure Design",
    "parameter-tampering": "A04:2021 - Insecure Design",
    "parameter-pollution": "A03:2021 - Injection",
    "host-header-injection": "A03:2021 - Injection",
    "framework-debug": "A05:2021 - Security Misconfiguration",
    "vulnerable-component": "A06:2021 - Vulnerable and Outdated Components",
    "web-cache-deception": "A05:2021 - Security Misconfiguration",
    "nosql-injection": "A03:2021 - Injection",
    "ldap-injection": "A03:2021 - Injection",
    "xpath-injection": "A03:2021 - Injection",
    "subdomain-takeover": "A05:2021 - Security Misconfiguration",
    "request-smuggling": "A03:2021 - Injection",
    "exposed-service": "A07:2021 - Identification and Authentication Failures",
    "prompt-injection": "A03:2021 - Injection",
    "llm-info-disclosure": "A04:2021 - Insecure Design",
    "iac-misconfig": "A05:2021 - Security Misconfiguration",
    "crlf-injection": "A03:2021 - Injection",
    "file-upload": "A04:2021 - Insecure Design",
    "csp": "A05:2021 - Security Misconfiguration",
    "exposed-secret": "A05:2021 - Security Misconfiguration",
    "formula-injection": "A03:2021 - Injection",
    "api-misconfig": "A05:2021 - Security Misconfiguration",
    "shadow-api": "A05:2021 - Security Misconfiguration",
    "directory-listing": "A05:2021 - Security Misconfiguration",
    "broken-authorization": "A01:2021 - Broken Access Control",
    "privilege-escalation": "A01:2021 - Broken Access Control",
    "mixed-content": "A02:2021 - Cryptographic Failures",
    "oauth-misconfig": "A07:2021 - Identification and Authentication Failures",
    "saml-misconfig": "A07:2021 - Identification and Authentication Failures",
    "grpc-reflection": "A05:2021 - Security Misconfiguration",
    "example": "A05:2021 - Security Misconfiguration",
}

# PCI-DSS v4.0 requirement references (most-relevant control per class).
PCI_DSS = {
    "sqli": "6.2.4", "xss": "6.2.4", "cmd-injection": "6.2.4", "ssti": "6.2.4",
    "lfi": "6.2.4", "xxe": "6.2.4", "ssrf": "6.2.4", "deserialization": "6.2.4",
    "prototype-pollution": "6.2.4", "idor": "7.2", "csrf": "6.2.4",
    "open-redirect": "6.2.4", "cors": "1.3", "security-headers": "6.4.1",
    "cache-poisoning": "6.4.1", "graphql": "6.4.1", "graphql-dos": "6.4.1",
    "auth-session": "8.3",
    "default-creds": "8.3.6", "jwt": "8.3", "tls": "4.2.1", "cve": "6.3.3",
    "exposed-file": "6.4.1", "websocket": "6.2.4", "race-condition": "6.2.4",
    "parameter-tampering": "6.2.4", "parameter-pollution": "6.2.4",
    "host-header-injection": "6.2.4", "framework-debug": "6.4.1",
    "vulnerable-component": "6.3.3", "dependency-confusion": "6.3.3",
    "web-cache-deception": "6.4.1",
    "nosql-injection": "6.2.4", "subdomain-takeover": "6.4.1",
    "ldap-injection": "6.2.4", "xpath-injection": "6.2.4",
    "crlf-injection": "6.2.4", "file-upload": "6.2.4",
    "request-smuggling": "6.2.4", "exposed-service": "1.3",
    "prompt-injection": "6.2.4", "llm-info-disclosure": "6.2.4",
    "iac-misconfig": "2.2",
    "csp": "6.4.1", "exposed-secret": "6.4.1", "formula-injection": "6.2.4",
    "api-misconfig": "6.4.1", "shadow-api": "6.4.1", "directory-listing": "6.4.1",
    "broken-authorization": "7.2", "privilege-escalation": "7.2", "mixed-content": "4.2.1",
    "oauth-misconfig": "6.2.4", "saml-misconfig": "6.2.4", "grpc-reflection": "6.4.1",
}

# NIST Cybersecurity Framework function/category.
NIST_CSF = {
    "tls": "PR.DS-2 (Data-in-transit)", "cve": "ID.RA-1 (Vulnerabilities identified)",
    "dependency-confusion": "ID.SC-2 (Supply chain risk)",
    "auth-session": "PR.AC-1 (Identities & credentials)",
    "default-creds": "PR.AC-1 (Identities & credentials)",
    "jwt": "PR.AC-7 (Authentication)", "idor": "PR.AC-4 (Access permissions)",
    "broken-authorization": "PR.AC-4 (Access permissions)",
    "privilege-escalation": "PR.AC-4 (Access permissions)",
}
_NIST_DEFAULT = "PR.IP-1 / PR.DS-5 (Secure config / data leak protection)"

# MITRE ATT&CK techniques.
MITRE_ATTACK = {
    "sqli": "T1190 Exploit Public-Facing App", "cmd-injection": "T1190 / T1059 Command Execution",
    "ssti": "T1190 Exploit Public-Facing App", "lfi": "T1083 File & Directory Discovery",
    "xxe": "T1190 Exploit Public-Facing App", "ssrf": "T1190 / T1090 Proxy",
    "xss": "T1059.007 JavaScript", "deserialization": "T1190 Exploit Public-Facing App",
    "default-creds": "T1078 Valid Accounts", "jwt": "T1550 Use Alternate Auth Material",
    "idor": "T1083 / T1530 Data from Cloud/Repo", "cve": "T1190 Exploit Public-Facing App",
    "exposed-file": "T1213 Data from Information Repositories",
    "tls": "T1040 Network Sniffing",
    "dependency-confusion": "T1195.001 Supply Chain Compromise: Software Dependencies",
}
_MITRE_DEFAULT = "T1190 Exploit Public-Facing Application"


def _embed_screenshot(path: str | None) -> str | None:
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "rb") as fh:
            data = base64.b64encode(fh.read()).decode("ascii")
        return f"data:image/png;base64,{data}"
    except OSError:
        return None


def _exploitation_dict(row: ExploitationRow, key: str | None) -> dict[str, Any]:
    def dec(v: str | None) -> str | None:
        return crypto.decrypt(v, key) if (key and v) else v

    return {
        "technique": row.technique,
        "success": row.success,
        "extracted_data": dec(row.extracted_data),
        "request_raw": dec(row.request_raw),
        "response_raw": dec(row.response_raw),
        "callback_id": row.callback_id,
        "screenshot": _embed_screenshot(row.screenshot_path),
    }


def _finding_dict(
    row: FindingRow, exploitations: list[ExploitationRow], key: str | None
) -> dict[str, Any]:
    vector = row.cvss_vector or DEFAULT_VECTORS.get(row.vuln_type)
    score = row.cvss_score
    if score is None and vector:
        score = base_score(vector)
    v4_vector, v4_score = v4_for(row.vuln_type)
    evidence = row.evidence_json or {}
    return {
        "id": row.id,
        "vuln_type": row.vuln_type,
        "title": row.title,
        "severity": row.severity,
        "confidence": row.confidence,
        "url": row.url,
        "parameter": row.parameter,
        "param_location": row.param_location,
        "cwe": row.cwe,
        "owasp": OWASP_2021.get(row.vuln_type, "Unmapped"),
        "pci_dss": PCI_DSS.get(row.vuln_type, "—"),
        "nist_csf": NIST_CSF.get(row.vuln_type, _NIST_DEFAULT),
        "mitre_attack": MITRE_ATTACK.get(row.vuln_type, _MITRE_DEFAULT),
        "attack": attack_for(row.vuln_type),  # structured ATT&CK techniques [{id,name,url}]
        "d3fend": d3fend_for(row.vuln_type),  # D3FEND countermeasures [{id,name}]
        "cvss_score": score,
        "cvss_vector": vector,
        "epss": epss_for_text(f"{row.title} {row.description}"),
        "cvss_v4_score": v4_score,
        "cvss_v4_vector": v4_vector,
        "scanner": row.scanner,
        "description": row.description,
        "remediation": row.remediation,
        "evidence": evidence,
        "screenshot": _embed_screenshot(evidence.get("screenshot_path")),
        "exploitations": [_exploitation_dict(e, key) for e in exploitations],
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


async def _build_context(
    store: Store, scan_id: str, branding: dict | None, min_severity: str | None
) -> dict[str, Any]:
    key = get_settings().encryption_key
    scan = await store.get_scan(scan_id)
    rows = await store.get_findings(scan_id)
    findings: list[dict[str, Any]] = []
    for row in rows:
        exploitations = await store.get_exploitations(row.id)
        findings.append(_finding_dict(row, exploitations, key))

    if min_severity:
        floor = _SEVERITY_ORDER.get(min_severity.lower(), 0)
        findings = [f for f in findings if _SEVERITY_ORDER.get(f["severity"], 0) >= floor]

    # Rank by severity tier first (a critical never drops below a medium), then by
    # EPSS exploit-probability, then CVSS — so actively-exploitable CVEs rise to
    # the top of their severity band.
    findings.sort(
        key=lambda f: (
            _SEVERITY_ORDER.get(f["severity"], 0),
            f.get("epss") or 0.0,
            f["cvss_score"] or 0.0,
        ),
        reverse=True,
    )

    counts = {sev: 0 for sev in _SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    confirmed = sum(1 for f in findings if f["confidence"] == "confirmed")

    owasp_counts: dict[str, int] = {}
    for f in findings:
        owasp_counts[f["owasp"]] = owasp_counts.get(f["owasp"], 0) + 1

    # Higher-order analysis over the raw findings: attack-path chains and a
    # deduplicated issue view. Computed over all rows (not the severity-filtered
    # display set) so a low-severity link can't hide a real chain.
    from orthrus.chains import correlate_findings
    from orthrus.triage import triage_findings

    chains = [c.to_dict() for c in correlate_findings(rows)]
    triage = triage_findings(rows).to_dict()

    return {
        "generated_at": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z"),
        "scan": {
            "id": scan_id,
            "target": scan.target if scan else None,
            "status": scan.status if scan else None,
            "started_at": scan.started_at.isoformat() if scan and scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan and scan.completed_at else None,
            "scope": scan.scope_json if scan else {},
        },
        "summary": {
            "total": len(findings),
            "confirmed": confirmed,
            "counts": counts,
            "owasp_counts": owasp_counts,
        },
        "findings": findings,
        "top_findings": findings[:5],
        "chains": chains,
        "triage": triage,
        "branding": _resolve_branding(branding),
    }


def _resolve_branding(branding: dict | None) -> dict:
    resolved = {"name": "Project ORTHRUS", "color": "#0b7285"}
    resolved.update(branding or {})
    logo_path = resolved.pop("logo", None)
    if logo_path and os.path.exists(logo_path):
        ext = os.path.splitext(logo_path)[1].lstrip(".").lower() or "png"
        try:
            with open(logo_path, "rb") as fh:
                resolved["logo_uri"] = (
                    f"data:image/{ext};base64,{base64.b64encode(fh.read()).decode('ascii')}"
                )
        except OSError:
            pass
    return resolved


def _render_html(context: dict[str, Any], template_name: str) -> str:
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    env = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=select_autoescape(["html"]),
    )
    return env.get_template(template_name).render(**context)


def _write_csv(findings: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["severity", "confidence", "cvss", "vuln_type", "title", "url",
         "parameter", "param_location", "cwe", "owasp"]
    )
    for f in findings:
        writer.writerow([
            f["severity"], f["confidence"], f["cvss_score"], f["vuln_type"],
            f["title"], f["url"], f["parameter"] or "", f["param_location"] or "",
            f["cwe"] or "", f["owasp"],
        ])
    return buf.getvalue()


# --------------------------------------------------------------------- Markdown
_SEVERITY_BADGE = {
    "critical": "`CRITICAL`",
    "high": "`HIGH`",
    "medium": "`MEDIUM`",
    "low": "`LOW`",
    "info": "`INFO`",
}


def _md_cell(value: object) -> str:
    """Sanitize a value for a Markdown table cell (escape pipes, flatten newlines)."""
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ").replace("\r", " ").strip()


def _write_markdown(context: dict[str, Any]) -> str:
    """A GitHub-flavored Markdown report (PR comments, issues, CI artifacts).

    Leads with scan metadata and a severity summary, then a sortable findings
    table, then a detail section per finding with description and remediation.
    """
    scan = context["scan"]
    summary = context["summary"]
    findings = context["findings"]
    counts = summary["counts"]

    lines: list[str] = []
    lines.append("# ORTHRUS Security Report")
    lines.append("")
    lines.append(f"**Target:** {scan.get('target') or '—'}  ")
    lines.append(f"**Scan ID:** `{scan.get('id') or '—'}`  ")
    lines.append(f"**Status:** {scan.get('status') or '—'}  ")
    lines.append(f"**Generated:** {context['generated_at']}")
    lines.append("")
    lines.append("> Authorized security testing only.")
    lines.append("")

    # --- summary ----------------------------------------------------------
    lines.append("## Summary")
    lines.append("")
    lines.append(f"**{summary['total']}** finding(s) · **{summary['confirmed']}** confirmed")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | ---: |")
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {_SEVERITY_BADGE.get(sev, sev)} | {counts.get(sev, 0)} |")
    lines.append("")

    owasp_counts = summary.get("owasp_counts") or {}
    if owasp_counts:
        lines.append("### OWASP Top 10 (2021)")
        lines.append("")
        lines.append("| Category | Count |")
        lines.append("| --- | ---: |")
        for cat, n in sorted(owasp_counts.items(), key=lambda kv: kv[1], reverse=True):
            lines.append(f"| {_md_cell(cat)} | {n} |")
        lines.append("")

    # --- attack paths -----------------------------------------------------
    chains = context.get("chains") or []
    if chains:
        lines.append("## Attack Paths")
        lines.append("")
        lines.append(
            f"{len(chains)} attacker-walkable path(s) — findings that combine into real "
            "compromise. Prioritise breaking these."
        )
        lines.append("")
        for c in chains:
            steps = " → ".join(f"{s['label']} (`{s['vuln_type']}`)" for s in c["steps"])
            lines.append(f"- **[{c['severity'].upper()}] {_md_cell(c['name'])}** "
                         f"on `{c['host']}`: {steps}")
            lines.append(f"  - _{_md_cell(c['impact'])}_")
        lines.append("")

    triage = context.get("triage") or {}
    if triage.get("collapsed"):
        lines.append(
            f"_Triaged to **{triage['unique']}** distinct issue(s) "
            f"({triage['collapsed']} duplicate finding(s) folded)._"
        )
        lines.append("")

    # --- findings ---------------------------------------------------------
    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("_No findings._")
        return "\n".join(lines) + "\n"

    lines.append("| # | Severity | CVSS | Type | Title | URL | Confidence |")
    lines.append("| ---: | --- | ---: | --- | --- | --- | --- |")
    for i, f in enumerate(findings, 1):
        lines.append(
            f"| {i} | {_SEVERITY_BADGE.get(f['severity'], f['severity'])} "
            f"| {f.get('cvss_score') if f.get('cvss_score') is not None else '—'} "
            f"| {_md_cell(f['vuln_type'])} | {_md_cell(f.get('title'))} "
            f"| {_md_cell(f['url'])} | {_md_cell(f.get('confidence'))} |"
        )
    lines.append("")

    lines.append("## Details")
    lines.append("")
    for i, f in enumerate(findings, 1):
        badge = _SEVERITY_BADGE.get(f["severity"], f["severity"])
        lines.append(f"### {i}. {f.get('title') or f['vuln_type']} — {badge}")
        lines.append("")
        meta = [
            ("Type", f["vuln_type"]),
            ("URL", f["url"]),
            ("Parameter", f.get("parameter")),
            ("CWE", f.get("cwe")),
            ("OWASP", f.get("owasp")),
            ("CVSS", f"{f.get('cvss_score')} ({f.get('cvss_vector')})" if f.get("cvss_score") else None),
            ("Confidence", f.get("confidence")),
            ("Scanner", f.get("scanner")),
        ]
        for label, value in meta:
            if value:
                lines.append(f"- **{label}:** {value}")
        lines.append("")
        if f.get("description"):
            lines.append("**Description**")
            lines.append("")
            lines.append(str(f["description"]))
            lines.append("")
        if f.get("remediation"):
            lines.append("**Remediation**")
            lines.append("")
            lines.append(str(f["remediation"]))
            lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(f"_Generated by ORTHRUS v{__version__}._")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------------ SARIF
# SARIF 2.1.0 is the lingua franca for CI security dashboards (GitHub code
# scanning, Azure DevOps, etc.). GitHub derives its severity bucket from the
# numeric `security-severity` property; `level` is the coarse error/warning/note.
ORTHRUS_URI = "https://github.com/anthropics/orthrus"
CHAIN_RULE_ID = "attack-path-chain"
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
# Fallback numeric severity (0-10) when a finding has no CVSS score, so a SARIF
# consumer can still bucket it (>=9 critical, >=7 high, >=4 medium, >=0.1 low).
_SEVERITY_SCORE = {"critical": 9.5, "high": 8.0, "medium": 5.0, "low": 3.0, "info": 0.0}


def _security_severity(f: dict[str, Any]) -> str:
    score = f.get("cvss_score")
    if score is None:
        score = _SEVERITY_SCORE.get(f["severity"], 0.0)
    return f"{float(score):.1f}"


def _rule_name(vuln_type: str) -> str:
    """Opaque PascalCase rule name, e.g. 'security-headers' -> 'SecurityHeaders'."""
    return "".join(part.capitalize() for part in vuln_type.replace("_", "-").split("-"))


def _cwe_tag(cwe: str | None) -> str | None:
    """GitHub recognizes `external/cwe/cwe-NN` tags for taxonomy mapping."""
    if not cwe:
        return None
    digits = "".join(ch for ch in cwe if ch.isdigit())
    return f"external/cwe/cwe-{digits}" if digits else None


def _finding_fingerprint(f: dict[str, Any]) -> str:
    """Stable hash so a consumer can track the same finding across runs."""
    raw = f"{f['vuln_type']}|{f['url']}|{f.get('parameter') or ''}|{f.get('param_location') or ''}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _severity_score_str(severity: str) -> str:
    return f"{_SEVERITY_SCORE.get(severity, 0.0):.1f}"


def _chain_results(chains: list[dict[str, Any]], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Render attack-path chains as SARIF results with a step-through codeFlow.

    Each chain becomes one result under a synthetic ``attack-path-chain`` rule; its
    steps populate a SARIF ``codeFlows``/``threadFlows`` so consumers (GitHub code
    scanning, etc.) render the path as an ordered walk-through, not a flat finding.
    """
    if not chains:
        return []
    rule_index = len(rules)
    rules.append({
        "id": CHAIN_RULE_ID,
        "name": "AttackPathChain",
        "shortDescription": {"text": "Correlated multi-step attack path"},
        "fullDescription": {
            "text": "Two or more findings that combine into an attacker-walkable kill-chain."
        },
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "attack-path"]},
    })

    results: list[dict[str, Any]] = []
    for c in chains:
        steps = c.get("steps") or []
        primary_uri = (steps[0].get("url") if steps else None) or c.get("host") or ORTHRUS_URI
        thread_locations = [
            {
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {"uri": s.get("url") or c.get("host") or ""}
                    },
                    "message": {"text": f"Step {i}: {s.get('label')} ({s.get('vuln_type')})"},
                }
            }
            for i, s in enumerate(steps, 1)
        ]
        fp = hashlib.sha256(
            f"{c.get('name')}|{c.get('host')}".encode()
        ).hexdigest()[:32]
        results.append({
            "ruleId": CHAIN_RULE_ID,
            "ruleIndex": rule_index,
            "level": _SARIF_LEVEL.get(c.get("severity", ""), "warning"),
            "message": {"text": f"Attack path: {c.get('name')} on {c.get('host')} — {c.get('impact')}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": primary_uri}}}],
            "codeFlows": [{"threadFlows": [{"locations": thread_locations}]}],
            "partialFingerprints": {"orthrusChainHash/v1": fp},
            "properties": {
                "security-severity": _severity_score_str(c.get("severity", "info")),
                "attack-path": True,
                "steps": [f"{s.get('label')} ({s.get('vuln_type')})" for s in steps],
            },
        })
    return results


def _write_sarif(context: dict[str, Any]) -> str:
    findings = context["findings"]
    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for f in findings:
        vt = f["vuln_type"]
        level = _SARIF_LEVEL.get(f["severity"], "warning")
        if vt not in rule_index:
            rule_index[vt] = len(rules)
            tags = ["security"]
            cwe_tag = _cwe_tag(f.get("cwe"))
            if cwe_tag:
                tags.append(cwe_tag)
            if f.get("owasp") and f["owasp"] != "Unmapped":
                tags.append(f["owasp"])
            rules.append({
                "id": vt,
                "name": _rule_name(vt),
                "shortDescription": {"text": (f.get("title") or vt)[:300]},
                "fullDescription": {"text": (f.get("description") or f.get("title") or vt)[:1000]},
                "defaultConfiguration": {"level": level},
                "properties": {"tags": tags, "security-severity": _security_severity(f)},
            })

        message = f.get("title") or vt
        if f.get("parameter"):
            message += f" (parameter: {f['parameter']})"
        message += f" at {f['url']}"
        props: dict[str, Any] = {
            "security-severity": _security_severity(f),
            "confidence": f.get("confidence"),
            "scanner": f.get("scanner"),
            "owasp": f.get("owasp"),
        }
        if f.get("cwe"):
            props["cwe"] = f["cwe"]
        if f.get("parameter"):
            props["parameter"] = f["parameter"]
        results.append({
            "ruleId": vt,
            "ruleIndex": rule_index[vt],
            "level": level,
            "message": {"text": message},
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": f["url"]}}}
            ],
            "partialFingerprints": {"orthrusFindingHash/v1": _finding_fingerprint(f)},
            "properties": props,
        })

    # Append correlated attack paths as codeFlow results under their own rule.
    results.extend(_chain_results(context.get("chains") or [], rules))

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ORTHRUS",
                        "informationUri": ORTHRUS_URI,
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False, default=str)


def _safe_output_path(output: str) -> str:
    """Make a user-supplied ``-o`` path safe to write on this OS.

    Tolerates a pasted URL as a filename (e.g. ``reports/https://site.com:8443.html``)
    by stripping the scheme and replacing characters that are illegal in a filename
    (``: / \\ * ? " < > |``) in the *basename* with ``-`` — turning what would be an
    OSError (or a silent NTFS alternate-data-stream write on Windows) into a real,
    predictable file. Directory and drive components are preserved.
    """
    import os
    import re

    cleaned = re.sub(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://", "", output)  # drop a pasted scheme
    head, tail = os.path.split(cleaned)
    tail = re.sub(r'[<>:"|?*\\/]', "-", tail) or "report"
    return os.path.join(head, tail) if head else tail


def _with_ext(output: str, ext: str) -> str:
    return output if output.endswith(f".{ext}") else f"{output}.{ext}"


async def _awrite(path: str, text: str) -> None:
    async with aiofiles.open(path, "w", encoding="utf-8", newline="") as fh:
        await fh.write(text)


def _write_stdout(text: str) -> None:
    """Write a text report to stdout as UTF-8, regardless of console locale.

    Prefers the binary buffer (correct on a Windows console / when piped); falls
    back to the text stream when it's been replaced (e.g. pytest capture).
    """
    import sys

    data = text if text.endswith("\n") else text + "\n"
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is not None:
        buffer.write(data.encode("utf-8"))
        buffer.flush()
    else:
        sys.stdout.write(data)


async def _emit(text: str, output: str, ext: str) -> str:
    """Persist a text report: to ``output`` (with extension) or stdout if "-".

    Returns the written path, or "-" to signal the report went to stdout.
    """
    if output == "-":
        _write_stdout(text)
        return "-"
    path = _with_ext(_safe_output_path(output), ext)
    await _awrite(path, text)
    return path


async def generate_report(
    store: Store,
    scan_id: str,
    fmt: str = "json",
    output: str = "orthrus_report",
    template: str = "technical",
    branding: dict | None = None,
    min_severity: str | None = None,
) -> str:
    fmt = fmt.lower()
    context = await _build_context(store, scan_id, branding, min_severity)

    if fmt == "json":
        return await _emit(
            json.dumps(context, indent=2, ensure_ascii=False, default=str), output, "json"
        )

    if fmt == "csv":
        return await _emit(_write_csv(context["findings"]), output, "csv")

    if fmt == "sarif":
        return await _emit(_write_sarif(context), output, "sarif")

    if fmt == "navigator":
        layer = build_navigator_layer(context["findings"], name=f"ORTHRUS {scan_id}")
        return await _emit(json.dumps(layer, indent=2, ensure_ascii=False), output, "json")

    if fmt in ("md", "markdown"):
        return await _emit(_write_markdown(context), output, "md")

    if fmt in ("html", "pdf"):
        tmpl = template if template in VALID_TEMPLATES else "technical"
        html = _render_html(context, f"{tmpl}.html")
        if fmt == "html":
            return await _emit(html, output, "html")
        # PDF is binary and renders from an HTML file on disk, so it can't stream.
        if output == "-":
            raise ValueError(
                "cannot stream a PDF report to stdout; use a text format "
                "(json/csv/sarif/md/html)"
            )
        html_path = _with_ext(output, "html")
        await _awrite(html_path, html)
        # PDF: render the HTML with headless Chromium.
        from orthrus.reporting.pdf import html_to_pdf

        pdf_path = _with_ext(output, "pdf")
        ok = await html_to_pdf(html_path, pdf_path)
        if not ok:
            logger.warning("PDF rendering unavailable (needs [browser] extra); kept HTML")
            return html_path
        return pdf_path

    raise ValueError(f"unsupported report format: {fmt}")


__all__ = ["generate_report", "OWASP_2021"]
