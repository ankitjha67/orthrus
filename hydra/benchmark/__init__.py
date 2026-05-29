"""Detection-accuracy benchmarking for HYDRA.

Scores a scan's findings against an enumerated ground-truth file for a target we
own, yielding a detection rate and a false-positive proxy. Used to measure scanner
quality as the engine evolves (PRD §13 — quality gates).
"""

from __future__ import annotations

from hydra.benchmark.runner import load_truth, run_benchmark
from hydra.benchmark.scorer import BenchmarkReport, Expected, match, score

__all__ = [
    "Expected",
    "BenchmarkReport",
    "match",
    "score",
    "load_truth",
    "run_benchmark",
]
