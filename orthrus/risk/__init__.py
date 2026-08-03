"""Risk governance layer (Glasswing / VVAH-aligned).

Deterministic, audit-traceable prioritisation and metrics that turn raw findings
into exploitability-first, business-contextual work items - the governance layer
Visa's Project Glasswing whitepaper stresses (MTTA, priority bands, "same
evidence -> same decision"). Pure and dependency-free so every decision is
reproducible and testable.
"""

from orthrus.risk.manifest import ScanManifest, build_manifest, write_manifest
from orthrus.risk.mtta import FindingRecord, MttaReport, compute_mtta
from orthrus.risk.policy import (
    Policy,
    PolicyDecision,
    apply_policies,
    default_policies,
    evaluate,
)
from orthrus.risk.priority import (
    PriorityAssessment,
    RiskContext,
    assess_priority,
    priority_band,
)
from orthrus.risk.sbom import Component, Vulnerability, build_sbom, write_sbom

__all__ = [
    "Component",
    "FindingRecord",
    "MttaReport",
    "Policy",
    "PolicyDecision",
    "PriorityAssessment",
    "RiskContext",
    "ScanManifest",
    "Vulnerability",
    "apply_policies",
    "assess_priority",
    "build_manifest",
    "build_sbom",
    "compute_mtta",
    "default_policies",
    "evaluate",
    "priority_band",
    "write_manifest",
    "write_sbom",
]
