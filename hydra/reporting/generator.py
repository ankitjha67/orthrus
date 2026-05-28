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

from hydra.db.models import Exploitation as ExploitationRow
from hydra.db.models import Finding as FindingRow
from hydra.db.store import Store
from hydra.reporting.cvss import DEFAULT_VECTORS, base_score
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


def _embed_screenshot(path: str | None) -> str | None:
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "rb") as fh:
            data = base64.b64encode(fh.read()).decode("ascii")
        return f"data:image/png;base64,{data}"
    except OSError:
        return None


def _exploitation_dict(row: ExploitationRow) -> dict[str, Any]:
    return {
        "technique": row.technique,
        "success": row.success,
        "extracted_data": row.extracted_data,
        "request_raw": row.request_raw,
        "response_raw": row.response_raw,
        "callback_id": row.callback_id,
        "screenshot": _embed_screenshot(row.screenshot_path),
    }


def _finding_dict(row: FindingRow, exploitations: list[ExploitationRow]) -> dict[str, Any]:
    vector = row.cvss_vector or DEFAULT_VECTORS.get(row.vuln_type)
    score = row.cvss_score
    if score is None and vector:
        score = base_score(vector)
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
        "cvss_score": score,
        "cvss_vector": vector,
        "scanner": row.scanner,
        "description": row.description,
        "remediation": row.remediation,
        "evidence": evidence,
        "screenshot": _embed_screenshot(evidence.get("screenshot_path")),
        "exploitations": [_exploitation_dict(e) for e in exploitations],
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


async def _build_context(store: Store, scan_id: str, branding: dict | None) -> dict[str, Any]:
    scan = await store.get_scan(scan_id)
    rows = await store.get_findings(scan_id)
    findings: list[dict[str, Any]] = []
    for row in rows:
        exploitations = await store.get_exploitations(row.id)
        findings.append(_finding_dict(row, exploitations))
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
        "branding": branding or {"name": "Project HYDRA", "color": "#0b7285"},
    }


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
) -> str:
    fmt = fmt.lower()
    context = await _build_context(store, scan_id, branding)

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
