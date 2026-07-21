"""Deterministic operator next-action planner (PRD §7.10, Phase 6)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from orthrus.model.planner import next_actions
from orthrus.model.store import ProgramGraph


def _graph(tmp_path, name="p.db") -> ProgramGraph:
    return ProgramGraph(f"sqlite+aiosqlite:///{(tmp_path / name).as_posix()}")


def _keys(actions) -> list[str]:
    return [a.key for a in actions]


def test_plan_recommends_recon_then_scan_then_triage(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        pid = (await g.create_program("Acme", "self-owned-lab", platform="self")).id
        await g.add_scope_entry(pid, "acme.test", entry_type="in", kind="domain")

        # 1. scoped, no assets → recon on top
        actions = await next_actions(g, pid, program_name="Acme")
        assert actions[0].key == "recon"
        assert "acme.test" not in actions[0].command  # command references the program, not scope
        assert all(0.0 <= a.priority <= 1.0 for a in actions)

        # 2. assets exist but never scanned → scan appears, ranked high
        await g.record_asset(pid, "subdomain", "www.acme.test")
        actions = await next_actions(g, pid, program_name="Acme")
        assert "scan" in _keys(actions)
        assert actions[0].key == "scan"          # 0.85, top of the list

        await g.close()

    asyncio.run(run())


def test_plan_prioritizes_high_severity_triage_and_regression(tmp_path):
    async def run():
        g = _graph(tmp_path, "p2.db")
        await g.init()
        pid = (await g.create_program("Acme", "self-owned-lab", platform="self")).id
        await g.record_asset(pid, "subdomain", "www.acme.test")
        run_row = await g.start_scan_run(pid)
        await g.finish_scan_run(run_row.id, status="completed")

        # a new high-severity finding → triage at the elevated priority
        f_hi, _ = await g.record_finding(pid, "sqli", "SQLi", "critical", "sig-hi",
                                         scan_run_id=run_row.id)
        actions = await next_actions(g, pid, program_name="Acme")
        triage = next(a for a in actions if a.key == "triage")
        assert triage.priority == 0.8 and "high/critical" in triage.reason
        assert triage.command == "orthrus program-findings --program Acme --status new"

        # confirm it, add a second confirmed one → 'report' action shows up
        await g.set_finding_status(f_hi.id, "confirmed")
        actions = await next_actions(g, pid, program_name="Acme")
        assert "report" in _keys(actions)
        assert "triage" not in _keys(actions)      # nothing 'new' remains

        # a regressed finding trumps everything
        f_reg, _ = await g.record_finding(pid, "xss", "XSS", "high", "sig-reg")
        await g.set_finding_status(f_reg.id, "regressed")
        actions = await next_actions(g, pid, program_name="Acme")
        assert actions[0].key == "reverify" and actions[0].priority == 0.95

        await g.close()

    asyncio.run(run())


def test_plan_flags_stale_recon(tmp_path):
    async def run():
        g = _graph(tmp_path, "p3.db")
        await g.init()
        pid = (await g.create_program("Acme", "self-owned-lab", platform="self")).id
        await g.record_asset(pid, "subdomain", "www.acme.test")
        run_row = await g.start_scan_run(pid)
        await g.finish_scan_run(run_row.id, status="completed")

        # evaluate "now" 30 days in the future → the run is stale
        future = datetime.now(UTC) + timedelta(days=30)
        actions = await next_actions(g, pid, now=future, program_name="Acme")
        recon = next((a for a in actions if a.key == "recon"), None)
        assert recon is not None and "30d ago" in recon.reason

        await g.close()

    asyncio.run(run())


def test_plan_empty_when_no_program(tmp_path):
    async def run():
        g = _graph(tmp_path, "p4.db")
        await g.init()
        # unknown program id → no state, no actions (never raises)
        assert await next_actions(g, "does-not-exist") == []
        await g.close()

    asyncio.run(run())


def test_plan_suggests_import_when_assets_have_no_routes(tmp_path):
    async def run():
        g = _graph(tmp_path, "p5.db")
        await g.init()
        pid = (await g.create_program("Acme", "self-owned-lab", platform="self")).id
        await g.record_asset(pid, "subdomain", "www.acme.test")
        run_row = await g.start_scan_run(pid)
        await g.finish_scan_run(run_row.id, status="completed")
        # assets + a scan run but zero endpoints → import-traffic suggestion present
        actions = await next_actions(g, pid, program_name="Acme")
        imp = next((a for a in actions if a.key == "import"), None)
        assert imp is not None and "import-traffic" in imp.command
        await g.close()

    asyncio.run(run())
