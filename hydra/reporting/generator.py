"""Report assembly (PRD §8).

Foundation scope: a structured JSON report that captures the full finding
inventory and scan metadata. The Jinja2 HTML/PDF executive, technical, and
compliance templates are Roadmap Phase 4 and slot in behind ``generate_report``.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import aiofiles

from hydra.db.models import Finding as FindingRow
from hydra.db.store import Store

DEFERRED_FORMATS = {"html", "pdf"}


def _finding_to_dict(row: FindingRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "vuln_type": row.vuln_type,
        "title": row.title,
        "severity": row.severity,
        "confidence": row.confidence,
        "url": row.url,
        "parameter": row.parameter,
        "cwe": row.cwe,
        "cvss_score": row.cvss_score,
        "cvss_vector": row.cvss_vector,
        "scanner": row.scanner,
        "description": row.description,
        "remediation": row.remediation,
        "evidence": row.evidence_json,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


async def generate_report(
    store: Store,
    scan_id: str,
    fmt: str = "json",
    output: str = "hydra_report",
) -> str:
    fmt = fmt.lower()
    if fmt in DEFERRED_FORMATS:
        raise NotImplementedError(
            f"'{fmt}' templates land in Roadmap Phase 4 (reporting); use --format json for now"
        )
    if fmt != "json":
        raise ValueError(f"unsupported report format: {fmt}")

    scan = await store.get_scan(scan_id)
    findings = await store.get_findings(scan_id)
    counts = await store.severity_counts(scan_id)

    report = {
        "generated_at": datetime.now().astimezone().isoformat(),
        "scan": {
            "id": scan_id,
            "target": scan.target if scan else None,
            "status": scan.status if scan else None,
            "started_at": scan.started_at.isoformat() if scan and scan.started_at else None,
            "completed_at": scan.completed_at.isoformat()
            if scan and scan.completed_at
            else None,
            "scope": scan.scope_json if scan else {},
        },
        "summary": {
            "total_findings": len(findings),
            "severity_counts": counts,
        },
        "findings": [_finding_to_dict(f) for f in findings],
    }

    path = output if output.endswith(".json") else f"{output}.json"
    text = json.dumps(report, indent=2, ensure_ascii=False)
    async with aiofiles.open(path, "w", encoding="utf-8") as fh:
        await fh.write(text)
    return path


__all__ = ["generate_report"]
