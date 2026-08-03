"""Mean Time to Adapt (MTTA) - the metric Glasswing puts at the centre.

The whitepaper defines MTTA as the time from an AI-discovered weakness to a
*validated fix in production*, tracked along three dimensions: inventory freshness,
exploitable paths per release, and validation cycle time.

Honest scope: ORTHRUS is a scanner, not a deploy pipeline, so it cannot see the
"fix landed in production" timestamp - and this module deliberately does not invent
one. It computes the part of MTTA a scanner *can* measure from the finding
lifecycle it owns:

* **Inventory freshness** - how current the picture is (time since the last scan).
* **Exploitable paths open** - open findings that are actually exploitable
  (high/critical severity, confirmed, or KEV) - "attack chains still possible",
  not just a raw open count.
* **Validation cycle time** - for a scanner, the analogue of the whitepaper's
  "time to produce evidence-backed proof" is **time-to-confirm**: discovery to a
  re-proven `confirmed` finding. Also reports time-to-file.

The production-fix leg of MTTA needs a resolved-at timestamp from the deploy
system; that is flagged, not faked. Pure and deterministic (``now`` is injected).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

# Statuses that mean the finding is no longer an open exposure.
CLOSED_STATUSES = frozenset({
    "verified_fixed", "closed", "out_of_scope", "duplicate", "not_reproducible",
})
_EXPLOITABLE_SEVERITY = frozenset({"high", "critical"})


def _dt(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            return None
    return None


def _hours_between(a: object, b: object) -> float | None:
    start, end = _dt(a), _dt(b)
    if start is None or end is None:
        return None
    return round((end - start).total_seconds() / 3600.0, 2)


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 2) if values else None


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    s = sorted(values)
    mid = len(s) // 2
    return round(s[mid] if len(s) % 2 else (s[mid - 1] + s[mid]) / 2, 2)


@dataclass(frozen=True)
class FindingRecord:
    """The lifecycle facts MTTA needs from one finding."""

    discovered_at: object
    status: str = "new"
    severity: str = "info"
    confidence: str = "tentative"
    kev: bool = False
    confirmed_at: object = None
    filed_at: object = None

    @classmethod
    def from_row(cls, row: dict) -> FindingRecord:
        return cls(
            discovered_at=row.get("discovered_at"),
            status=str(row.get("status", "new")).lower(),
            severity=str(row.get("severity", "info")).lower(),
            confidence=str(row.get("confidence", "tentative")).lower(),
            kev=bool(row.get("kev_flag") or row.get("kev")),
            confirmed_at=row.get("confirmed_at"),
            filed_at=row.get("filed_at"),
        )

    @property
    def is_open(self) -> bool:
        return self.status.lower() not in CLOSED_STATUSES

    @property
    def is_exploitable(self) -> bool:
        return (
            self.severity.lower() in _EXPLOITABLE_SEVERITY
            or self.confidence.lower() == "confirmed"
            or self.kev
        )


@dataclass(frozen=True)
class MttaReport:
    now: str
    latest_scan_at: str | None
    inventory_freshness_hours: float | None
    open_total: int
    open_exploitable: int
    open_by_severity: dict[str, int] = field(default_factory=dict)
    mean_time_to_confirm_hours: float | None = None
    median_time_to_confirm_hours: float | None = None
    mean_time_to_file_hours: float | None = None
    verified_fixed: int = 0
    regressed: int = 0
    total: int = 0

    def as_dict(self) -> dict:
        return {
            "now": self.now,
            "latest_scan_at": self.latest_scan_at,
            "inventory_freshness_hours": self.inventory_freshness_hours,
            "open_total": self.open_total,
            "open_exploitable": self.open_exploitable,
            "open_by_severity": self.open_by_severity,
            "mean_time_to_confirm_hours": self.mean_time_to_confirm_hours,
            "median_time_to_confirm_hours": self.median_time_to_confirm_hours,
            "mean_time_to_file_hours": self.mean_time_to_file_hours,
            "verified_fixed": self.verified_fixed,
            "regressed": self.regressed,
            "total": self.total,
        }


def compute_mtta(
    records: list[FindingRecord],
    *,
    now: object,
    latest_scan_at: object = None,
) -> MttaReport:
    """Compute the scanner-observable MTTA dimensions from lifecycle records."""
    now_dt = _dt(now)
    now_iso = now_dt.isoformat() if now_dt else str(now)

    open_records = [r for r in records if r.is_open]
    open_by_severity: dict[str, int] = {}
    for r in open_records:
        open_by_severity[r.severity] = open_by_severity.get(r.severity, 0) + 1

    ttc = [h for r in records if (h := _hours_between(r.discovered_at, r.confirmed_at)) is not None]
    ttf = [h for r in records if (h := _hours_between(r.discovered_at, r.filed_at)) is not None]

    latest_dt = _dt(latest_scan_at)
    freshness = _hours_between(latest_scan_at, now) if latest_dt is not None else None

    return MttaReport(
        now=now_iso,
        latest_scan_at=latest_dt.isoformat() if latest_dt else None,
        inventory_freshness_hours=freshness,
        open_total=len(open_records),
        open_exploitable=sum(1 for r in open_records if r.is_exploitable),
        open_by_severity=dict(sorted(open_by_severity.items())),
        mean_time_to_confirm_hours=_mean(ttc),
        median_time_to_confirm_hours=_median(ttc),
        mean_time_to_file_hours=_mean(ttf),
        verified_fixed=sum(1 for r in records if r.status.lower() == "verified_fixed"),
        regressed=sum(1 for r in records if r.status.lower() == "regressed"),
        total=len(records),
    )


__all__ = ["FindingRecord", "MttaReport", "compute_mtta", "CLOSED_STATUSES"]
