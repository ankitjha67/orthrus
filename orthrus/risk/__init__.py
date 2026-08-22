"""Risk governance layer (Glasswing / VVAH-aligned).

Deterministic, audit-traceable prioritisation and metrics that turn raw findings
into exploitability-first, business-contextual work items - the governance layer
Visa's Project Glasswing whitepaper stresses (MTTA, priority bands, "same
evidence -> same decision"). Pure and dependency-free so every decision is
reproducible and testable.
"""

from orthrus.risk.dedup import (
    DedupeResult,
    ReconcileResult,
    dedupe_findings,
    finding_hash,
    reconcile,
)
from orthrus.risk.fix_validation import GateResult, ValidationResult, run_ladder
from orthrus.risk.manifest import ScanManifest, build_manifest, write_manifest
from orthrus.risk.memory_ledger import (
    DEAD_CLASS_THRESHOLD,
    MemoryLedger,
    SkipDecision,
    load_ledger,
    rollup,
    save_ledger,
    skip_decision,
    tech_stack_signature,
)
from orthrus.risk.memory_ledger import (
    FindingRecord as LedgerFindingRecord,
)
from orthrus.risk.mtta import FindingRecord, MttaReport, compute_mtta
from orthrus.risk.novelty import (
    KNOWN_PATTERNS,
    KnownPattern,
    NoveltyVerdict,
    assess_novelty,
    partition_by_novelty,
)
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
from orthrus.risk.sla import (
    SLAPolicy,
    SLAReport,
    SLAStatus,
    default_sla_policy,
    evaluate_slas,
    sla_alert_lines,
    sla_status,
)

__all__ = [
    "Component",
    "DEAD_CLASS_THRESHOLD",
    "DedupeResult",
    "FindingRecord",
    "GateResult",
    "LedgerFindingRecord",
    "KNOWN_PATTERNS",
    "KnownPattern",
    "MemoryLedger",
    "NoveltyVerdict",
    "ReconcileResult",
    "SkipDecision",
    "ValidationResult",
    "MttaReport",
    "Policy",
    "PolicyDecision",
    "PriorityAssessment",
    "RiskContext",
    "ScanManifest",
    "SLAPolicy",
    "SLAReport",
    "SLAStatus",
    "Vulnerability",
    "apply_policies",
    "assess_novelty",
    "assess_priority",
    "partition_by_novelty",
    "build_manifest",
    "build_sbom",
    "compute_mtta",
    "dedupe_findings",
    "default_policies",
    "finding_hash",
    "reconcile",
    "default_sla_policy",
    "evaluate",
    "evaluate_slas",
    "load_ledger",
    "priority_band",
    "rollup",
    "run_ladder",
    "save_ledger",
    "skip_decision",
    "sla_alert_lines",
    "sla_status",
    "tech_stack_signature",
    "write_manifest",
    "write_sbom",
]
