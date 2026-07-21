"""Operator-graph Notes DAL (PRD §6.1/§7.13)."""

from __future__ import annotations

import asyncio

import pytest

from orthrus.model.store import ProgramGraph


def _graph(tmp_path) -> ProgramGraph:
    return ProgramGraph(f"sqlite+aiosqlite:///{(tmp_path / 'notes.db').as_posix()}")


def test_note_crud_and_search(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        pid = (await g.create_program("Acme", "self-owned-lab", platform="self")).id

        n1 = await g.add_note("Cloudflare WAF bypass", "use JSON body + header casing",
                              program_id=pid, tags=["waf", "cloudflare"])
        await g.add_note("SQLi cheatsheet", "union based order by", program_id=pid, tags=["sqli"])
        assert n1.id and n1.title == "Cloudflare WAF bypass"

        assert len(await g.list_notes(program_id=pid)) == 2
        # search across title / body / tags
        assert [n.title for n in await g.search_notes("cloudflare", program_id=pid)] == ["Cloudflare WAF bypass"]
        assert len(await g.search_notes("union", program_id=pid)) == 1     # body match
        assert len(await g.search_notes("waf", program_id=pid)) == 1       # tag match
        assert await g.search_notes("nonexistent", program_id=pid) == []

        updated = await g.update_note(n1.id, markdown="updated body", tags=["waf", "json"])
        assert updated.markdown == "updated body" and "json" in updated.tags

        assert await g.delete_note(n1.id) is True
        assert await g.get_note(n1.id) is None
        assert len(await g.list_notes(program_id=pid)) == 1

        with pytest.raises(ValueError, match="title is required"):
            await g.add_note("  ", program_id=pid)
        await g.close()

    asyncio.run(run())


def test_notes_filter_by_finding(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        pid = (await g.create_program("Acme", "self-owned-lab", platform="self")).id
        f, _ = await g.record_finding(pid, "sqli", "SQLi", "high", "sig")
        await g.add_note("re: this bug", "notes", program_id=pid, finding_id=f.id)
        await g.add_note("general", "x", program_id=pid)
        assert len(await g.list_notes(program_id=pid)) == 2
        assert [n.title for n in await g.list_notes(finding_id=f.id)] == ["re: this bug"]
        await g.close()

    asyncio.run(run())
