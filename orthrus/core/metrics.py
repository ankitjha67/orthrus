"""Per-scanner execution metrics (PRD §11 observability).

A production scanner needs to answer "which module found what, how much traffic
did it cost, and how long did it take?" - for tuning, for spotting a module that
hammers the target for nothing, and for catching a scanner that silently
crashed. The orchestrator records one :class:`ScannerMetric` per module that
actually ran; everything here is pure so the aggregation is unit-testable.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ScannerMetric:
    """What a single scanner cost and produced during one scan."""

    name: str
    findings: int = 0
    requests: int = 0
    duration_s: float = 0.0
    error: str | None = None

    @property
    def requests_per_second(self) -> float:
        return self.requests / self.duration_s if self.duration_s > 0 else 0.0

    def summary_line(self) -> str:
        """One-line audit string (persisted to the scan log)."""
        base = (
            f"{self.name}: findings={self.findings} requests={self.requests} "
            f"time={self.duration_s:.2f}s"
        )
        return f"{base} error={self.error}" if self.error else base


def top_scanners(metrics: list[ScannerMetric], *, by: str = "findings") -> list[ScannerMetric]:
    """Metrics sorted most-to-least significant.

    Default ranks by findings (then requests, then duration) so the modules that
    matter most surface first; ``by='requests'`` / ``by='duration'`` re-key for
    cost analysis. Stable and non-mutating.
    """
    if by == "requests":
        key = lambda m: (m.requests, m.findings, m.duration_s)  # noqa: E731
    elif by == "duration":
        key = lambda m: (m.duration_s, m.findings, m.requests)  # noqa: E731
    else:
        key = lambda m: (m.findings, m.requests, m.duration_s)  # noqa: E731
    return sorted(metrics, key=key, reverse=True)


def totals(metrics: list[ScannerMetric]) -> ScannerMetric:
    """Aggregate across all scanners (name='total'); error counts crashed modules."""
    crashed = sum(1 for m in metrics if m.error)
    return ScannerMetric(
        name="total",
        findings=sum(m.findings for m in metrics),
        requests=sum(m.requests for m in metrics),
        duration_s=sum(m.duration_s for m in metrics),
        error=f"{crashed} crashed" if crashed else None,
    )


__all__ = ["ScannerMetric", "top_scanners", "totals"]
