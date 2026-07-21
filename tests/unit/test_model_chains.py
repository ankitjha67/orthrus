"""Operator-graph attack-chain edges + rule-based correlation (PRD §7.8)."""

from __future__ import annotations

import asyncio

import pytest

from orthrus.model.chains import correlate_program_chains
from orthrus.model.store import ProgramGraph


def _graph(tmp_path, name="chains.db") -> ProgramGraph:
    return ProgramGraph(f"sqlite+aiosqlite:///{(tmp_path / name).as_posix()}")


def test_finding_chain_dal_dedup_and_validation(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        pid = (await g.create_program("Acme", "self-owned-lab", platform="self")).id
        a, _ = await g.record_finding(pid, "ssrf", "SSRF", "high", "s-a")
        b, _ = await g.record_finding(pid, "exposed-service", "Exposed svc", "high", "s-b")

        edge, is_new = await g.add_finding_chain(a.id, b.id, "enables", confidence=0.9)
        assert is_new and edge.relationship == "enables"
        # dedup on (from, to, relationship)
        _edge2, is_new2 = await g.add_finding_chain(a.id, b.id, "enables")
        assert is_new2 is False
        assert len(await g.list_finding_chains(pid)) == 1

        with pytest.raises(ValueError, match="relationship must be one of"):
            await g.add_finding_chain(a.id, b.id, "bogus")
        with pytest.raises(ValueError, match="cannot chain to itself"):
            await g.add_finding_chain(a.id, a.id, "enables")

        assert (await g.accept_finding_chain(edge.id)).accepted_by_user is True
        assert await g.remove_finding_chain(edge.id) is True
        assert await g.list_finding_chains(pid) == []
        await g.close()

    asyncio.run(run())


def test_correlate_materializes_curated_chains(tmp_path):
    async def run():
        g = _graph(tmp_path, "chains2.db")
        await g.init()
        pid = (await g.create_program("Acme", "self-owned-lab", platform="self")).id
        # SSRF + exposed-service -> "SSRF -> internal-service compromise" rule fires
        await g.record_finding(pid, "ssrf", "SSRF", "high", "sig-ssrf")
        await g.record_finding(pid, "exposed-service", "Internal svc exposed", "high", "sig-exp")
        # an unrelated finding that chains with nothing
        await g.record_finding(pid, "security-headers", "Missing HSTS", "low", "sig-hdr")

        created = await correlate_program_chains(g, pid)
        assert len(created) == 1
        edge = created[0]
        assert edge.relationship == "enables" and edge.proposed_by == "rules"
        assert edge.confidence == 0.9 and "SSRF" in edge.narrative_md

        # idempotent: a second correlation adds nothing new
        assert await correlate_program_chains(g, pid) == []
        assert len(await g.list_finding_chains(pid)) == 1
        await g.close()

    asyncio.run(run())


def test_correlate_noop_without_pairs(tmp_path):
    async def run():
        g = _graph(tmp_path, "chains3.db")
        await g.init()
        pid = (await g.create_program("Acme", "self-owned-lab", platform="self")).id
        await g.record_finding(pid, "ssrf", "SSRF only", "high", "sig-solo")
        assert await correlate_program_chains(g, pid) == []   # no downstream match
        await g.close()

    asyncio.run(run())
