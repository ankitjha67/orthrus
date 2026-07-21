"""Promote scan findings into the operator graph (PRD §7.5, Phase 2).

The bridge from the v0.1 scan engine to the v2.0 triage queue: each
``schemas.Finding`` a scan produced becomes a program-anchored
:class:`ProgramFinding`, keyed by a cross-tool ``signature`` (so two tools that
find the same bug collapse to one) and scored with the composite priority the
bounty triage engine already computes. Deduplicated by ``(program, signature)``;
optionally linked to the ``ScanRun`` that found it.
"""

from __future__ import annotations

from orthrus.bounty.report import _host, _norm_title
from orthrus.bounty.triage import priority_score
from orthrus.model.entities import FINDING_CONFIDENCES
from orthrus.model.store import ProgramGraph


def finding_signature(finding) -> str:
    """Cross-tool dedup key: class + host + normalized title."""
    return f"{(finding.vuln_type or '').lower()}|{_host(finding.url)}|{_norm_title(finding.title)}"


def _confidence(finding) -> str:
    value = getattr(getattr(finding, "confidence", None), "value", "tentative")
    return value if value in FINDING_CONFIDENCES else "tentative"


async def promote_findings(
    graph: ProgramGraph,
    program_id: str,
    findings: list,
    *,
    scan_run_id: str | None = None,
) -> dict[str, int]:
    """Fold ``findings`` into the program's ProgramFinding queue; return counts."""
    counts = {"seen": 0, "new": 0, "duplicate": 0}
    for finding in findings:
        counts["seen"] += 1
        _row, is_new = await graph.record_finding(
            program_id,
            finding.vuln_type,
            finding.title,
            getattr(getattr(finding, "severity", None), "value", "info"),
            finding_signature(finding),
            confidence=_confidence(finding),
            found_by_tool=getattr(finding, "scanner", None) or "unknown",
            scan_run_id=scan_run_id,
            cwe_id=getattr(finding, "cwe", None),
            cvss_v3_score=getattr(finding, "cvss_score", None),
            cvss_v3_vector=getattr(finding, "cvss_vector", None),
            priority_score=priority_score(finding),
        )
        counts["new" if is_new else "duplicate"] += 1
    return counts


__all__ = ["promote_findings", "finding_signature"]
