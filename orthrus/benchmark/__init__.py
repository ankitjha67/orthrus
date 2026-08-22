"""Detection-accuracy benchmarking for ORTHRUS.

Scores a scan's findings against an enumerated ground-truth file for a target we
own, yielding a detection rate and a false-positive proxy. Used to measure scanner
quality as the engine evolves (PRD §13 - quality gates).
"""

from __future__ import annotations

from orthrus.benchmark.ps_labs import (
    DEFAULT_LAB_CATALOG,
    EvalReport,
    LabResult,
    LabSpec,
    check_via_oracle,
    parse_lab_status,
    run_lab_eval,
    solve_rates,
)
from orthrus.benchmark.runner import load_truth, run_benchmark
from orthrus.benchmark.scorer import BenchmarkReport, Expected, match, score

__all__ = [
    "Expected",
    "BenchmarkReport",
    "DEFAULT_LAB_CATALOG",
    "EvalReport",
    "LabResult",
    "LabSpec",
    "check_via_oracle",
    "match",
    "parse_lab_status",
    "run_benchmark",
    "run_lab_eval",
    "score",
    "solve_rates",
    "load_truth",
]
