"""Risk governance layer (Glasswing / VVAH-aligned).

Deterministic, audit-traceable prioritisation and metrics that turn raw findings
into exploitability-first, business-contextual work items - the governance layer
Visa's Project Glasswing whitepaper stresses (MTTA, priority bands, "same
evidence -> same decision"). Pure and dependency-free so every decision is
reproducible and testable.
"""

from orthrus.risk.manifest import ScanManifest, build_manifest, write_manifest
from orthrus.risk.mtta import FindingRecord, MttaReport, compute_mtta
from orthrus.risk.priority import (
    PriorityAssessment,
    RiskContext,
    assess_priority,
    priority_band,
)

__all__ = [
    "FindingRecord",
    "MttaReport",
    "PriorityAssessment",
    "RiskContext",
    "ScanManifest",
    "assess_priority",
    "build_manifest",
    "compute_mtta",
    "priority_band",
    "write_manifest",
]
