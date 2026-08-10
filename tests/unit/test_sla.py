"""Remediation SLA engine (per-severity deadlines, breach states, alerts)."""

from __future__ import annotations

from datetime import UTC, datetime

from orthrus.risk.sla import (
    BREACHED,
    BREACHED_LATE,
    DUE_SOON,
    MET,
    NO_SLA,
    ON_TRACK,
    default_sla_policy,
    evaluate_slas,
    sla_alert_lines,
    sla_status,
)

NOW = datetime(2026, 1, 31, tzinfo=UTC)


def _f(**kw: object) -> dict:
    return kw


def test_default_policy_budgets() -> None:
    p = default_sla_policy()
    assert p.days_by_severity["critical"] == 7
    assert p.days_by_severity["high"] == 30
    assert p.days_by_severity["low"] == 180


def test_on_track_and_due_soon_and_breached() -> None:
    p = default_sla_policy()
    on_track = sla_status(_f(severity="high", discovered_at="2026-01-26", status="open"), p, NOW)
    assert on_track.state == ON_TRACK and on_track.days_remaining > 7.5

    due = sla_status(_f(severity="high", discovered_at="2026-01-05", status="open"), p, NOW)
    assert due.state == DUE_SOON and 0 <= due.days_remaining <= 7.5

    breached = sla_status(_f(severity="critical", discovered_at="2026-01-20", status="open"), p, NOW)
    assert breached.state == BREACHED and breached.days_remaining < 0


def test_closed_on_time_is_met_and_late_is_breached_late() -> None:
    p = default_sla_policy()
    met = sla_status(
        _f(severity="medium", discovered_at="2025-12-01", status="verified_fixed",
           resolved_at="2025-12-20"),
        p, NOW,
    )
    assert met.state == MET

    late = sla_status(
        _f(severity="high", discovered_at="2025-11-01", status="closed",
           resolved_at="2026-01-15"),
        p, NOW,
    )
    assert late.state == BREACHED_LATE


def test_no_sla_when_unknown_severity_or_missing_timestamp() -> None:
    p = default_sla_policy()
    assert sla_status(_f(severity="cosmetic", discovered_at="2026-01-01"), p, NOW).state == NO_SLA
    assert sla_status(_f(severity="high"), p, NOW).state == NO_SLA  # no discovered_at


def test_evaluate_and_alerts() -> None:
    findings = [
        _f(id="A", severity="critical", discovered_at="2026-01-20", status="open"),  # breached
        _f(id="B", severity="high", discovered_at="2026-01-05", status="open"),       # due_soon
        _f(id="C", severity="high", discovered_at="2026-01-28", status="open"),       # on_track
        _f(id="D", severity="medium", discovered_at="2025-12-01", status="closed",
           resolved_at="2025-12-10"),                                                 # met
    ]
    report = evaluate_slas(findings, now=NOW)
    assert report.counts.get(BREACHED) == 1
    assert report.counts.get(DUE_SOON) == 1
    assert report.compliant is False
    assert report.breached[0].finding_id == "A"

    lines = sla_alert_lines(report)
    assert any("BREACHED" in ln and "A" in ln for ln in lines)
    assert any("due soon" in ln and "B" in ln for ln in lines)


def test_compliant_when_nothing_open_overdue() -> None:
    findings = [_f(id="C", severity="high", discovered_at="2026-01-28", status="open")]
    report = evaluate_slas(findings, now=NOW)
    assert report.compliant is True
    assert sla_alert_lines(report) == []
