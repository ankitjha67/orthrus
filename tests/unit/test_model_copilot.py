"""Copilot retrieval over the operator graph (PRD §7.7)."""

from __future__ import annotations

import asyncio

from orthrus.model.copilot import retrieve
from orthrus.model.store import ProgramGraph


def test_retrieve_over_findings_and_notes(tmp_path):
    async def run():
        g = ProgramGraph(f"sqlite+aiosqlite:///{(tmp_path / 'c.db').as_posix()}")
        await g.init()
        pid = (await g.create_program("Acme", "self-owned-lab", platform="self")).id
        await g.record_finding(pid, "ssrf.oob", "SSRF to cloud metadata", "high", "sig1",
                               found_by_tool="orthrus")
        await g.add_note("Cloudflare WAF bypass", "json body + header casing trick",
                         program_id=pid, tags=["waf", "cloudflare"])

        # a finding-matching query surfaces the finding
        hits = await retrieve(g, pid, "ssrf metadata", k=5)
        assert hits and hits[0].source.startswith("finding:")
        assert "metadata" in hits[0].title.lower()

        # a note-matching query surfaces the note
        hits2 = await retrieve(g, pid, "cloudflare waf bypass", k=5)
        assert hits2 and hits2[0].source.startswith("note:")

        # nothing relevant → empty (grounded: never invents)
        assert await retrieve(g, pid, "quantumcryptozoology") == []
        await g.close()

    asyncio.run(run())


def test_retrieve_scoped_to_program(tmp_path):
    async def run():
        g = ProgramGraph(f"sqlite+aiosqlite:///{(tmp_path / 'c2.db').as_posix()}")
        await g.init()
        a = (await g.create_program("Acme", "self-owned-lab", platform="self")).id
        b = (await g.create_program("Beta", "self-owned-lab", platform="self")).id
        await g.record_finding(a, "sqli", "SQL injection", "high", "s")
        # Beta's copilot sees nothing from Acme
        assert await retrieve(g, b, "SQL injection") == []
        assert await retrieve(g, a, "SQL injection")
        await g.close()

    asyncio.run(run())
