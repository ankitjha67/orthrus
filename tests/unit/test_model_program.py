"""v2.0 operator graph: Program + ScopeEntry DAL (PRD §6.1)."""

from __future__ import annotations

import asyncio

import pytest

from orthrus.model.store import ProgramGraph


def _graph(tmp_path) -> ProgramGraph:
    return ProgramGraph(f"sqlite+aiosqlite:///{(tmp_path / 'graph.db').as_posix()}")


def test_create_and_fetch_program(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        p = await g.create_program("Acme", "https://hackerone.com/acme", platform="h1")
        assert p.id and p.name == "Acme" and p.platform == "h1"
        assert p.priority == 3 and p.is_paused is False

        assert (await g.get_program(p.id)).name == "Acme"
        assert (await g.get_program_by_name("Acme")).id == p.id
        assert [x.name for x in await g.list_programs()] == ["Acme"]
        await g.close()

    asyncio.run(run())


def test_authorization_is_required_deny_by_default(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        with pytest.raises(ValueError, match="authorization_source is required"):
            await g.create_program("NoAuth", "")
        with pytest.raises(ValueError, match="program name is required"):
            await g.create_program("", "self-owned-lab")
        with pytest.raises(ValueError, match="platform must be one of"):
            await g.create_program("Bad", "self-owned-lab", platform="nope")
        await g.close()

    asyncio.run(run())


def test_update_and_pause(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        p = await g.create_program("Acme", "self-owned-lab", platform="self")
        updated = await g.update_program(p.id, is_paused=True, priority=1)
        assert updated.is_paused is True and updated.priority == 1
        # can't clear authorization
        with pytest.raises(ValueError, match="cannot be cleared"):
            await g.update_program(p.id, authorization_source="")
        assert await g.update_program("nonexistent", priority=2) is None
        await g.close()

    asyncio.run(run())


def test_scope_entries_in_out_and_active_filter(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        p = await g.create_program("Acme", "direct:written-ok", platform="direct")
        await g.add_scope_entry(p.id, "*.acme.com", entry_type="in", kind="domain")
        out = await g.add_scope_entry(p.id, "admin.acme.com", entry_type="out")
        await g.add_scope_entry(p.id, "0xdeadbeef", entry_type="in", kind="contract")

        assert len(await g.scope_entries(p.id)) == 3
        await g.deactivate_scope_entry(out.id)
        active = await g.scope_entries(p.id)
        assert len(active) == 2 and all(e.is_active for e in active)
        assert len(await g.scope_entries(p.id, active_only=False)) == 3

        with pytest.raises(ValueError, match="kind must be one of"):
            await g.add_scope_entry(p.id, "x", kind="bogus")
        with pytest.raises(ValueError, match="entry_type must be one of"):
            await g.add_scope_entry(p.id, "x", entry_type="maybe")
        await g.close()

    asyncio.run(run())


def test_delete_program_cascades_scope(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        p = await g.create_program("Acme", "self-owned-lab", platform="self")
        await g.add_scope_entry(p.id, "*.acme.com")
        assert await g.delete_program(p.id) is True
        assert await g.get_program(p.id) is None
        assert await g.scope_entries(p.id, active_only=False) == []   # cascaded
        assert await g.delete_program(p.id) is False
        await g.close()

    asyncio.run(run())
