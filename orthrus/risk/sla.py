"""Remediation SLA engine - per-severity deadlines, breach state, alerts.

The governance layer already measures *how fast* remediation happens (MTTA); this
adds the *commitment*: a per-severity remediation budget (critical in 7 days,
high in 30, …), a deadline per finding, and a breach state the notifier can act
on. It answers "what is overdue right now, and what breaches this week" - the
operational half of the Glasswing "same evidence -> same decision" stance.

Pure and deterministic: ``now`` is injected, timestamps come from the finding
lifecycle ORTHRUS owns (discovered_at, status, resolved_at). Findings without a
budget for their severity are reported ``no_sla`` rather than guessed at.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

# Statuses that mean the finding is remediated / no longer an open exposure.
CLOSED_STATUSES = frozenset({
    "verified_fixed", "closed", "resolved", "out_of_scope", "duplicate", "not_reproducible",
})

# Default remediation budget (calendar days) by severity - a common baseline.
DEFAULT_SLA_DAYS: dict[str, int] = {
    "critical": 7,
    "high": 30,
    "medium": 90,
    "low": 180,
    "info": 365,
}

# States a finding's SLA can be in.
ON_TRACK, DUE_SOON, BREACHED, MET, BREACHED_LATE, NO_SLA = (
    "on_track", "due_soon", "breached", "met", "breached_late", "no_sla"
)


@dataclass(frozen=True)
class SLAPolicy:
    """Per-severity remediation budgets and the 'due soon' warning band."""

    days_by_severity: dict[str, int]
    warn_ratio: float = 0.25  # 'due_soon' once <=25% of the budget remains


def default_sla_policy() -> SLAPolicy:
    return SLAPolicy(dict(DEFAULT_SLA_DAYS))


@dataclass(frozen=True)
class SLAStatus:
    finding_id: str
    severity: str
    budget_days: int | None
    deadline: str | None  # ISO-8601, or None when no budget applies
    days_remaining: float | None  # negative => overdue; None when no budget
    state: str


@dataclass
class SLAReport:
    now: str
    counts: dict[str, int] = field(default_factory=dict)
    breached: list[SLAStatus] = field(default_factory=list)
    due_soon: list[SLAStatus] = field(default_factory=list)
    statuses: list[SLAStatus] = field(default_factory=list)

    @property
    def open_breached(self) -> int:
        return self.counts.get(BREACHED, 0)

    @property
    def compliant(self) -> bool:
        """True when nothing open is currently past its deadline."""
        return self.open_breached == 0


def _dt(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            return None
    return None


def _get(finding: object, *names: str) -> object:
    for name in names:
        if isinstance(finding, dict):
            if name in finding and finding[name] is not None:
                return finding[name]
        else:
            val = getattr(finding, name, None)
            if val is not None:
                return val
    return None


def _severity(finding: object) -> str:
    sev = _get(finding, "severity")
    sev = getattr(sev, "value", sev)  # accept enum or str
    return str(sev).lower() if sev is not None else "info"


def sla_status(finding: object, policy: SLAPolicy, now: datetime) -> SLAStatus:
    """Compute the SLA state of one finding against ``now``."""
    fid = str(_get(finding, "id", "finding_id", "title") or "?")
    severity = _severity(finding)
    budget = policy.days_by_severity.get(severity)
    created = _dt(_get(finding, "discovered_at", "created_at", "first_seen", "timestamp"))

    if budget is None or created is None:
        return SLAStatus(fid, severity, budget, None, None, NO_SLA)

    deadline = created + timedelta(days=budget)
    status = str(_get(finding, "status") or "open").lower()
    closed = status in CLOSED_STATUSES
    resolved = _dt(_get(finding, "resolved_at", "fixed_at", "closed_at"))
    if closed and resolved is None:
        resolved = now  # closed but no timestamp -> treat as closed at 'now'

    deadline_iso = deadline.isoformat(timespec="seconds")

    if closed:
        remaining = round((deadline - resolved).total_seconds() / 86400.0, 2)
        state = MET if resolved <= deadline else BREACHED_LATE
        return SLAStatus(fid, severity, budget, deadline_iso, remaining, state)

    remaining = round((deadline - now).total_seconds() / 86400.0, 2)
    if remaining < 0:
        state = BREACHED
    elif remaining <= budget * policy.warn_ratio:
        state = DUE_SOON
    else:
        state = ON_TRACK
    return SLAStatus(fid, severity, budget, deadline_iso, remaining, state)


def evaluate_slas(
    findings: list[object], policy: SLAPolicy | None = None, now: datetime | None = None
) -> SLAReport:
    """Compute SLA states across all findings and aggregate the breaches."""
    policy = policy or default_sla_policy()
    now = now or datetime.now(UTC)
    report = SLAReport(now=now.isoformat(timespec="seconds"))
    for finding in findings:
        st = sla_status(finding, policy, now)
        report.statuses.append(st)
        report.counts[st.state] = report.counts.get(st.state, 0) + 1
        if st.state == BREACHED:
            report.breached.append(st)
        elif st.state == DUE_SOON:
            report.due_soon.append(st)
    # Most overdue first (most negative days_remaining).
    report.breached.sort(key=lambda s: s.days_remaining if s.days_remaining is not None else 0)
    report.due_soon.sort(key=lambda s: s.days_remaining if s.days_remaining is not None else 0)
    return report


def sla_alert_lines(report: SLAReport) -> list[str]:
    """Human-readable notifier lines for the pre/post-breach conditions."""
    lines: list[str] = []
    for st in report.breached:
        overdue = abs(st.days_remaining) if st.days_remaining is not None else 0
        lines.append(
            f"SLA BREACHED: {st.finding_id} ({st.severity}) is {overdue:.0f} day(s) overdue "
            f"(deadline {st.deadline})."
        )
    for st in report.due_soon:
        lines.append(
            f"SLA due soon: {st.finding_id} ({st.severity}) is due in "
            f"{st.days_remaining:.0f} day(s) (deadline {st.deadline})."
        )
    return lines


__all__ = [
    "SLAPolicy",
    "SLAStatus",
    "SLAReport",
    "DEFAULT_SLA_DAYS",
    "default_sla_policy",
    "sla_status",
    "evaluate_slas",
    "sla_alert_lines",
]
