"""Report assembly (PRD §8): JSON, CSV, HTML (Jinja2), and PDF (Chromium).

Builds a single report context from stored findings — CVSS-scored, OWASP-mapped,
with confirmation evidence and base64-embedded screenshots — then renders it to
the requested format. The executive/technical/compliance HTML templates live in
``reporting/templates``.
"""

from __future__ import annotations

import base64
import csv
import io
import json
import os
from datetime import datetime
from typing import Any

import aiofiles

from hydra.core.config import get_settings
from hydra.db.models import Exploitation as ExploitationRow
from hydra.db.models import Finding as FindingRow
from hydra.db.store import Store
from hydra.reporting.cvss import DEFAULT_VECTORS, base_score, v4_for
from hydra.utils import crypto
from hydra.utils.logger import get_logger

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
    "exposed-file": "A05:2021 - Security Misconfiguration",
    "websocket": "A05:2021 - Security Misconfiguration",
    "auth-session": "A07:2021 - Identification and Authentication Failures",
    "jwt": "A07:2021 - Identification and Authentication Failures",
    "deserialization": "A08:2021 - Software and Data Integrity Failures",
    "prototype-pollution": "A08:2021 - Software and Data Integrity Failures",
    "tls": "A02:2021 - Cryptographic Failures",
    "cve": "A06:2021 - Vulnerable and Outdated Components",
    "default-creds": "A07:2021 - Identification and Authentication Failures",
    "race-condition": "A04:2021 - Insecure Design",
    "example": "A05:2021 - Security Misconfiguration",
}

# PCI-DSS v4.0 requirement references (most-relevant control per class).
PCI_DSS = {
    "sqli": "6.2.4", "xss": "6.2.4", "cmd-injection": "6.2.4", "ssti": "6.2.4",
    "lfi": "6.2.4", "xxe": "6.2.4", "ssrf": "6.2.4", "deserialization": "6.2.4",
    "prototype-pollution": "6.2.4", "idor": "7.2", "csrf": "6.2.4",
    "open-redirect": "6.2.4", "cors": "1.3", "security-headers": "6.4.1",
    "cache-poisoning": "6.4.1", "graphql": "6.4.1", "auth-session": "8.3",
    "default-creds": "8.3.6", "jwt": "8.3", "tls": "4.2.1", "cve": "6.3.3",
    "exposed-file": "6.4.1", "websocket": "6.2.4", "race-condition": "6.2.4",
}

# NIST Cybersecurity Framework function/category.
NIST_CSF = {
    "tls": "PR.DS-2 (Data-in-transit)", "cve": "ID.RA-1 (Vulnerabilities identified)",
    "auth-session": "PR.AC-1 (Identities & credentials)",
    "default-creds": "PR.AC-1 (Identities & credentials)",
    "jwt": "PR.AC-7 (Authentication)", "idor": "PR.AC-4 (Access permissions)",
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
        "cwe": row.cwe,
        "owasp": OWASP_2021.get(row.vuln_type, "Unmapped"),
        "pci_dss": PCI_DSS.get(row.vuln_type, "—"),
        "nist_csf": NIST_CSF.get(row.vuln_type, _NIST_DEFAULT),
        "mitre_attack": MITRE_ATTACK.get(row.vuln_type, _MITRE_DEFAULT),
        "cvss_score": score,
        "cvss_vector": vector,
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

    findings.sort(key=lambda f: (f["cvss_score"] or 0.0), reverse=True)

    counts = {sev: 0 for sev in _SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    confirmed = sum(1 for f in findings if f["confidence"] == "confirmed")

    owasp_counts: dict[str, int] = {}
    for f in findings:
        owasp_counts[f["owasp"]] = owasp_counts.get(f["owasp"], 0) + 1

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
        "branding": _resolve_branding(branding),
    }


def _resolve_branding(branding: dict | None) -> dict:
    resolved = {"name": "Project HYDRA", "color": "#0b7285"}
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
        ["severity", "confidence", "cvss", "vuln_type", "title", "url", "parameter", "cwe", "owasp"]
    )
    for f in findings:
        writer.writerow([
            f["severity"], f["confidence"], f["cvss_score"], f["vuln_type"],
            f["title"], f["url"], f["parameter"] or "", f["cwe"] or "", f["owasp"],
        ])
    return buf.getvalue()


def _with_ext(output: str, ext: str) -> str:
    return output if output.endswith(f".{ext}") else f"{output}.{ext}"


async def _awrite(path: str, text: str) -> None:
    async with aiofiles.open(path, "w", encoding="utf-8", newline="") as fh:
        await fh.write(text)


async def generate_report(
    store: Store,
    scan_id: str,
    fmt: str = "json",
    output: str = "hydra_report",
    template: str = "technical",
    branding: dict | None = None,
    min_severity: str | None = None,
) -> str:
    fmt = fmt.lower()
    context = await _build_context(store, scan_id, branding, min_severity)

    if fmt == "json":
        path = _with_ext(output, "json")
        await _awrite(path, json.dumps(context, indent=2, ensure_ascii=False, default=str))
        return path

    if fmt == "csv":
        path = _with_ext(output, "csv")
        await _awrite(path, _write_csv(context["findings"]))
        return path

    if fmt in ("html", "pdf"):
        tmpl = template if template in VALID_TEMPLATES else "technical"
        html = _render_html(context, f"{tmpl}.html")
        html_path = _with_ext(output, "html")
        await _awrite(html_path, html)
        if fmt == "html":
            return html_path
        # PDF: render the HTML with headless Chromium.
        from hydra.reporting.pdf import html_to_pdf

        pdf_path = _with_ext(output, "pdf")
        ok = await html_to_pdf(html_path, pdf_path)
        if not ok:
            logger.warning("PDF rendering unavailable (needs [browser] extra); kept HTML")
            return html_path
        return pdf_path

    raise ValueError(f"unsupported report format: {fmt}")


__all__ = ["generate_report", "OWASP_2021"]
