"""v2.0 operator graph: findings dedup, evidence, hash-chained audit, cost (PRD §6.1)."""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import update

from orthrus.model.entities import AuditLogRow
from orthrus.model.store import ProgramGraph


def _graph(tmp_path) -> ProgramGraph:
    return ProgramGraph(f"sqlite+aiosqlite:///{(tmp_path / 'f.db').as_posix()}")


async def _program(g) -> str:
    return (await g.create_program("Acme", "self-owned-lab", platform="self")).id


def test_finding_dedup_and_priority_order(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        pid = await _program(g)
        f1, new1 = await g.record_finding(pid, "xss.reflected", "XSS", "high", "sig-xss",
                                          priority_score=80, found_by_tool="dalfox")
        assert new1 is True
        # a second tool reporting the same signature dedups
        f2, new2 = await g.record_finding(pid, "xss.reflected", "XSS again", "high", "sig-xss",
                                          found_by_tool="nuclei")
        assert new2 is False and f2.id == f1.id and f2.found_by_tool == "dalfox"

        await g.record_finding(pid, "sqli.error", "SQLi", "critical", "sig-sqli", priority_score=95)
        await g.record_finding(pid, "info", "Info", "info", "sig-info")  # priority None
        ordered = await g.list_findings(pid)
        assert [f.signature for f in ordered] == ["sig-sqli", "sig-xss", "sig-info"]  # None last

        with pytest.raises(ValueError, match="confidence must be one of"):
            await g.record_finding(pid, "x", "t", "low", "s2", confidence="bogus")
        await g.close()

    asyncio.run(run())


def test_finding_status_transitions_stamp_timestamps(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        pid = await _program(g)
        f, _ = await g.record_finding(pid, "ssrf.oob", "SSRF", "high", "sig")
        assert f.status == "new" and f.confirmed_at is None

        confirmed = await g.set_finding_status(f.id, "confirmed")
        assert confirmed.status == "confirmed" and confirmed.confirmed_at is not None
        filed = await g.set_finding_status(f.id, "filed")
        assert filed.filed_at is not None
        with pytest.raises(ValueError, match="status must be one of"):
            await g.set_finding_status(f.id, "not-a-status")
        assert await g.set_finding_status("nope", "closed") is None
        await g.close()

    asyncio.run(run())


def test_evidence_is_content_addressable(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        pid = await _program(g)
        f, _ = await g.record_finding(pid, "xss.reflected", "XSS", "high", "sig")
        ev = await g.add_evidence(f.id, "request", "/blobs/req1", content=b"GET / HTTP/1.1")
        assert len(ev.content_hash) == 64 and ev.size_bytes == 14
        # explicit hash path also works
        ev2 = await g.add_evidence(f.id, "screenshot", "/blobs/s.png", content_hash="a" * 64)
        assert ev2.content_hash == "a" * 64
        with pytest.raises(ValueError, match="content=.*or an explicit content_hash"):
            await g.add_evidence(f.id, "log", "/blobs/x")
        await g.close()

    asyncio.run(run())


def test_audit_chain_detects_tampering(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        r1 = await g.append_audit("program-created", "create", subject_type="program",
                                  subject_id="p1", details={"name": "Acme"})
        await g.append_audit("scan-started", "scan", subject_id="s1")
        await g.append_audit("finding-confirmed", "confirm", subject_id="f1")
        assert r1.prev_hash is None and len(r1.row_hash) == 64

        ok, bad = await g.verify_audit()
        assert ok is True and bad == -1

        # tamper with the middle row's details directly in the DB
        async with g._session() as s:
            await s.execute(
                update(AuditLogRow).where(AuditLogRow.subject_id == "s1")
                .values(details={"hacked": True})
            )
            await s.commit()
        ok2, bad2 = await g.verify_audit()
        assert ok2 is False and bad2 >= 1     # pinpoints the tampered row
        await g.close()

    asyncio.run(run())


def test_cost_summary_rolls_up(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        pid = await _program(g)
        await g.record_cost("llm", "anthropic", 1000, "tokens", 0.015, program_id=pid)
        await g.record_cost("oast", "cloudflare", 1, "domain", 1.0, program_id=pid)
        await g.record_cost("llm", "anthropic", 500, "tokens", 0.0075)  # no program

        summ = await g.cost_summary()
        assert summ["entries"] == 3
        assert summ["by_category"]["llm"] == 0.0225 and summ["by_provider"]["cloudflare"] == 1.0
        assert summ["total_usd"] == 1.0225

        per_program = await g.cost_summary(pid)
        assert per_program["entries"] == 2 and per_program["total_usd"] == 1.015
        await g.close()

    asyncio.run(run())
