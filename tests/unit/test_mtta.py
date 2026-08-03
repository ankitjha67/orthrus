"""Tests for the scanner-observable MTTA metric."""

from __future__ import annotations

from orthrus.risk.mtta import FindingRecord, compute_mtta

BASE = "2026-01-01T00:00:00+00:00"
CONFIRMED = "2026-01-01T02:00:00+00:00"   # +2h
FILED = "2026-01-03T00:00:00+00:00"       # +48h
NOW = "2026-01-10T00:00:00+00:00"
LATEST_SCAN = "2026-01-09T12:00:00+00:00"  # 12h before now


def _records():
    return [
        FindingRecord(BASE, "confirmed", "high", "confirmed", confirmed_at=CONFIRMED),
        FindingRecord(BASE, "new", "low", "tentative"),
        FindingRecord(BASE, "verified_fixed", "medium", "firm"),
        FindingRecord(BASE, "triaging", "medium", "firm", kev=True),
        FindingRecord(BASE, "filed", "high", "confirmed", filed_at=FILED),
        FindingRecord(BASE, "regressed", "critical", "confirmed"),
    ]


def test_is_open_and_is_exploitable():
    assert FindingRecord(BASE, "new", "low", "tentative").is_open
    assert not FindingRecord(BASE, "verified_fixed", "high").is_open
    assert FindingRecord(BASE, "new", "high").is_exploitable       # severity
    assert FindingRecord(BASE, "new", "low", "confirmed").is_exploitable  # confidence
    assert FindingRecord(BASE, "new", "low", kev=True).is_exploitable     # KEV
    assert not FindingRecord(BASE, "new", "low", "tentative").is_exploitable


def test_from_row_maps_lifecycle_fields():
    r = FindingRecord.from_row({
        "discovered_at": BASE, "status": "Filed", "severity": "High",
        "confidence": "Confirmed", "kev_flag": True, "confirmed_at": CONFIRMED,
    })
    assert r.status == "filed" and r.severity == "high" and r.kev is True
    assert r.is_open and r.is_exploitable


def test_open_and_exploitable_counts():
    rep = compute_mtta(_records(), now=NOW, latest_scan_at=LATEST_SCAN)
    assert rep.total == 6
    assert rep.open_total == 5           # all but verified_fixed
    assert rep.open_exploitable == 4     # high, kev, high, critical (not the low/tentative)
    assert rep.open_by_severity == {"critical": 1, "high": 2, "low": 1, "medium": 1}
    assert rep.verified_fixed == 1 and rep.regressed == 1


def test_validation_cycle_times():
    rep = compute_mtta(_records(), now=NOW, latest_scan_at=LATEST_SCAN)
    assert rep.mean_time_to_confirm_hours == 2.0     # only r1 has confirmed_at, +2h
    assert rep.median_time_to_confirm_hours == 2.0
    assert rep.mean_time_to_file_hours == 48.0       # only r5 has filed_at, +48h


def test_inventory_freshness():
    rep = compute_mtta(_records(), now=NOW, latest_scan_at=LATEST_SCAN)
    assert rep.inventory_freshness_hours == 12.0


def test_empty_and_missing_data_do_not_crash():
    rep = compute_mtta([], now=NOW)
    assert rep.open_total == 0 and rep.total == 0
    assert rep.inventory_freshness_hours is None       # no latest scan supplied
    assert rep.mean_time_to_confirm_hours is None      # nothing confirmed


def test_naive_timestamps_are_treated_as_utc():
    # A naive discovered_at + tz-aware confirmed_at must still diff cleanly.
    r = FindingRecord("2026-01-01T00:00:00", "confirmed", "high", confirmed_at="2026-01-01T03:00:00")
    rep = compute_mtta([r], now=NOW)
    assert rep.mean_time_to_confirm_hours == 3.0


def test_report_is_json_serialisable():
    import json
    rep = compute_mtta(_records(), now=NOW, latest_scan_at=LATEST_SCAN)
    assert json.loads(json.dumps(rep.as_dict()))["open_exploitable"] == 4
