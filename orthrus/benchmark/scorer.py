"""Detection-accuracy scoring (pure, offline).

Given a list of :class:`~orthrus.core.schemas.Finding` objects produced by a scan
and a list of :class:`Expected` ground-truth entries describing what *should* be
found on a known target, this computes:

* **detection rate** — fraction of (required) expected vulnerabilities that the
  scan actually flagged, and
* **unexpected findings** — findings that match no ground-truth entry, used as a
  false-positive proxy on a target whose vulnerabilities are fully enumerated.

The module is deliberately dependency-free (no DB, no network) so it can be unit
tested in isolation and reused by the benchmark runner and the CLI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from orthrus.core.schemas import Finding


@dataclass(frozen=True)
class Expected:
    """One ground-truth vulnerability we expect a scan to detect.

    A finding matches when its ``vuln_type`` is equal (case-insensitive), its URL
    contains ``url_contains``, and — when ``param`` is set — the finding's
    parameter matches. ``optional`` marks vulnerabilities that need a deferred
    capability (e.g. a real browser for DOM/stored XSS); they are tracked but do
    not drag down the headline detection rate.
    """

    vuln_type: str
    url_contains: str = ""
    param: str | None = None
    note: str = ""
    optional: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Expected:
        try:
            vuln_type = str(data["vuln_type"]).strip()
        except KeyError as exc:
            raise ValueError("ground-truth entry missing 'vuln_type'") from exc
        if not vuln_type:
            raise ValueError("ground-truth entry has an empty 'vuln_type'")
        param = data.get("param")
        return cls(
            vuln_type=vuln_type,
            url_contains=str(data.get("url_contains", "")),
            param=None if param is None else str(param),
            note=str(data.get("note", "")),
            optional=bool(data.get("optional", False)),
        )

    @property
    def label(self) -> str:
        loc = self.url_contains or "*"
        return f"{self.vuln_type} @ {loc}" + (f" (param={self.param})" if self.param else "")


def match(finding: Finding, expected: Expected) -> bool:
    """True when ``finding`` satisfies the ``expected`` ground-truth entry."""
    if finding.vuln_type.strip().lower() != expected.vuln_type.strip().lower():
        return False
    if expected.url_contains and expected.url_contains not in finding.url:
        return False
    if expected.param is not None and (finding.parameter or "") != expected.param:
        return False
    return True


@dataclass
class BenchmarkReport:
    """Outcome of scoring a scan's findings against ground truth."""

    detected: list[Expected] = field(default_factory=list)
    missed: list[Expected] = field(default_factory=list)
    unexpected: list[Finding] = field(default_factory=list)
    total_findings: int = 0

    # -- required (headline) detection ------------------------------------
    @property
    def required_total(self) -> int:
        return sum(1 for e in self.detected + self.missed if not e.optional)

    @property
    def required_detected(self) -> int:
        return sum(1 for e in self.detected if not e.optional)

    @property
    def detection_rate(self) -> float:
        """Fraction of required ground-truth vulns detected (0.0–1.0)."""
        total = self.required_total
        return self.required_detected / total if total else 1.0

    # -- optional (capability-gated) detection ----------------------------
    @property
    def optional_total(self) -> int:
        return sum(1 for e in self.detected + self.missed if e.optional)

    @property
    def optional_detected(self) -> int:
        return sum(1 for e in self.detected if e.optional)

    # -- false-positive proxy ---------------------------------------------
    @property
    def unexpected_count(self) -> int:
        return len(self.unexpected)

    @property
    def false_positive_rate(self) -> float:
        """Fraction of reported findings that matched no ground-truth entry."""
        return self.unexpected_count / self.total_findings if self.total_findings else 0.0


def score(findings: list[Finding], expected: list[Expected]) -> BenchmarkReport:
    """Match ``findings`` against ``expected`` ground truth and tally results.

    A single finding can satisfy at most the entries it matches; any finding that
    matches no entry is reported as *unexpected* (a false-positive candidate).
    """
    detected: list[Expected] = []
    missed: list[Expected] = []
    accounted: set[int] = set()

    for entry in expected:
        matches = [f for f in findings if match(f, entry)]
        if matches:
            detected.append(entry)
            accounted.update(id(f) for f in matches)
        else:
            missed.append(entry)

    unexpected = [f for f in findings if id(f) not in accounted]
    return BenchmarkReport(
        detected=detected,
        missed=missed,
        unexpected=unexpected,
        total_findings=len(findings),
    )


__all__ = ["Expected", "BenchmarkReport", "match", "score"]
