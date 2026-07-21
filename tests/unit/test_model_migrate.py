"""v0.1 → v2.0 data migration (PRD §4.2): additive, idempotent, reversible."""

from __future__ import annotations

import asyncio

from orthrus.core import schemas
from orthrus.db.store import Store
from orthrus.model.migrate import LEGACY_PROGRAM_NAME, migrate_v01
from orthrus.model.store import ProgramGraph


def _finding(vt: str, sev: schemas.Severity, url: str) -> schemas.Finding:
    return schemas.Finding(
        vuln_type=vt, title=f"{vt} finding", severity=sev,
        confidence=schemas.Confidence.FIRM, url=url, scanner=vt,
        evidence=schemas.Evidence(),
    )


async def _seed(db_url: str) -> None:
    store = Store(db_url)
    await store.init()
    await store.create_scan("s1", "https://acme.com", {}, {})
    await store.add_asset("s1", schemas.Asset(fqdn="api.acme.com", discovery_method="crawler"))
    await store.add_asset("s1", schemas.Asset(fqdn="1.2.3.4"))
    await store.add_finding("s1", _finding("sqli", schemas.Severity.HIGH, "https://api.acme.com/x"))
    await store.add_finding("s1", _finding("xss", schemas.Severity.MEDIUM, "https://api.acme.com/y"))
    await store.close()


def test_migrate_promotes_v01_scans(tmp_path):
    db = f"sqlite+aiosqlite:///{(tmp_path / 'm.db').as_posix()}"

    async def run():
        await _seed(db)
        store = Store(db)
        graph = ProgramGraph(db)
        await store.init()

        # dry-run writes nothing
        dry = await migrate_v01(store, graph, dry_run=True)
        assert dry["scans"] == 1 and dry["assets_seen"] == 2 and dry["findings_seen"] == 2
        assert dry["program_id"] is None
        assert await graph.list_programs() == []

        # real run promotes into a legacy program
        res = await migrate_v01(store, graph)
        assert res["assets_new"] == 2 and res["findings_new"] == 2
        progs = await graph.list_programs()
        assert [p.name for p in progs] == [LEGACY_PROGRAM_NAME]
        pid = progs[0].id
        assets = await graph.list_assets(pid)
        assert {a.kind for a in assets} == {"subdomain", "ip"}
        assert len(await graph.list_findings(pid)) == 2

        # idempotent: a second run adds nothing (dedup by identity/signature)
        res2 = await migrate_v01(store, graph)
        assert res2["assets_new"] == 0 and res2["findings_new"] == 0
        assert len(await graph.list_programs()) == 1

        # reversible: the v0.1 tables are untouched
        assert len(await store.get_assets("s1")) == 2

        await store.close()
        await graph.close()

    asyncio.run(run())
