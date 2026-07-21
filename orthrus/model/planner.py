"""Deterministic next-action planner over the operator graph (PRD §7.10, Phase 6).

The bounded "operator agent" in its honest, no-hallucination form: it inspects
real graph state - assets, endpoints, findings, scan history, scope - and proposes
the concrete next commands to run, each grounded in counts it can point at. No LLM,
no invented steps: an operator asks "what next on this program?" and gets an
explainable, ranked to-do list of commands that actually exist. An LLM narrative
layer can sit on top of this later without ever being able to fabricate a step.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from orthrus.model.store import ProgramGraph

_STALE_RECON_DAYS = 7          # re-run recon if the newest scan run is older than this
_JUICY_THRESHOLD = 0.7         # an endpoint at/above this is "high-value"
_HIGH_SEVERITIES = {"critical", "high"}
# statuses that still need operator work, vs. terminal ones that don't.
_NEEDS_TRIAGE = "new"
_READY_TO_FILE = "confirmed"
_REGRESSED = "regressed"


@dataclass
class PlannedAction:
    """One grounded, ranked next step: what to do, why, and the exact command."""

    key: str            # stable action kind: recon | scan | triage | report | reverify | import
    priority: float     # 0..1 - higher runs sooner
    reason: str         # explanation grounded in real counts
    command: str        # a concrete, runnable orthrus command


def _age_days(dt: datetime | None, now: datetime) -> float | None:
    """Whole days between an (naive-or-aware) timestamp and ``now``; None if absent."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return (now - dt).total_seconds() / 86400.0


async def next_actions(
    graph: ProgramGraph, program_id: str, *,
    now: datetime | None = None, program_name: str | None = None,
) -> list[PlannedAction]:
    """Rank the concrete next steps for a program from its current graph state."""
    now = now or datetime.now(UTC)
    program = await graph.get_program(program_id)
    if program is None:
        return []  # nothing to plan for a program that isn't there
    name = program_name or program.name

    assets = await graph.list_assets(program_id)                 # non-noise
    alive = [a for a in assets if a.is_alive]
    endpoints = await graph.list_endpoints(program_id)
    findings = await graph.list_findings(program_id)
    runs = await graph.list_scan_runs(program_id, limit=1)
    scope = await graph.scope_entries(program_id)
    has_in_scope = any(se.entry_type == "in" for se in scope)

    actions: list[PlannedAction] = []

    # regressed findings first - a bug we'd fixed is back; re-verify immediately.
    regressed = [f for f in findings if f.status == _REGRESSED]
    if regressed:
        actions.append(PlannedAction(
            "reverify", 0.95,
            f"{len(regressed)} finding(s) regressed - a previously-resolved bug is back",
            f"orthrus program-scan --program {name}"))

    # no surface yet → recon (if scoped) so there's something to scan.
    if not assets:
        if has_in_scope:
            actions.append(PlannedAction(
                "recon", 0.9,
                "no assets discovered yet - enumerate the in-scope domains",
                f"orthrus recon-run --program {name}"))
        else:
            actions.append(PlannedAction(
                "recon", 0.6,
                "program has no in-scope entries - add scope, then recon",
                f"orthrus recon-run --program {name} --in-scope <domain> "
                f"--authorization <source>"))

    # live assets that have never been scanned → first scan.
    if alive and not runs:
        actions.append(PlannedAction(
            "scan", 0.85,
            f"{len(alive)} live asset(s) discovered but never scanned",
            f"orthrus program-scan --program {name}"))

    # new findings awaiting triage - high/critical bumps the priority.
    new = [f for f in findings if f.status == _NEEDS_TRIAGE]
    if new:
        hi = [f for f in new if (f.severity or "").lower() in _HIGH_SEVERITIES]
        actions.append(PlannedAction(
            "triage", 0.8 if hi else 0.6,
            f"{len(new)} new finding(s) awaiting triage"
            + (f", {len(hi)} high/critical" if hi else ""),
            f"orthrus program-findings --program {name} --status new"))

    # confirmed but not yet filed → write up + submit.
    confirmed = [f for f in findings if f.status == _READY_TO_FILE]
    if confirmed:
        actions.append(PlannedAction(
            "report", 0.7,
            f"{len(confirmed)} confirmed finding(s) ready to file",
            f"orthrus program-findings --program {name} --status confirmed"))

    # high-value endpoints imported (e.g. from Burp/Caido) but nothing found yet → scan.
    juicy = [e for e in endpoints if (e.juicy_score or 0.0) >= _JUICY_THRESHOLD]
    if juicy and not findings and runs:
        actions.append(PlannedAction(
            "scan", 0.65,
            f"{len(juicy)} high-value endpoint(s) imported but no findings yet",
            f"orthrus program-scan --program {name}"))

    # stale recon - newest run older than the freshness window.
    if runs and (age := _age_days(runs[0].started_at, now)) is not None \
            and age >= _STALE_RECON_DAYS:
        actions.append(PlannedAction(
            "recon", 0.5,
            f"last scan run was {int(age)}d ago - re-run recon for drift",
            f"orthrus recon-run --program {name}"))

    # a scoped program with assets but no endpoints mapped → suggest importing traffic.
    if alive and not endpoints:
        actions.append(PlannedAction(
            "import", 0.4,
            "assets known but no routes mapped - import a Burp/Caido/HAR session",
            f"orthrus import-traffic <export-file> --program {name}"))

    actions.sort(key=lambda a: a.priority, reverse=True)
    return actions


__all__ = ["PlannedAction", "next_actions"]
