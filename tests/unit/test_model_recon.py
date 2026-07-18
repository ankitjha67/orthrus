"""v2.0 operator graph: Asset dedup + ScanRun lifecycle (PRD §6.1/§7.2)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from orthrus.model.store import ProgramGraph


def _graph(tmp_path) -> ProgramGraph:
    return ProgramGraph(f"sqlite+aiosqlite:///{(tmp_path / 'recon.db').as_posix()}")


async def _program(g) -> str:
    p = await g.create_program("Acme", "self-owned-lab", platform="self")
    return p.id


def test_record_asset_dedups_by_identity(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        pid = await _program(g)

        asset, is_new = await g.record_asset(pid, "subdomain", "api.acme.com", discovered_by="crtsh")
        assert is_new is True and asset.first_seen_at == asset.last_seen_at

        # re-seeing the same identity updates, doesn't duplicate
        again, is_new2 = await g.record_asset(pid, "subdomain", "api.acme.com", discovered_by="dnsx")
        assert is_new2 is False and again.id == asset.id
        assert again.last_seen_at >= again.first_seen_at
        assert len(await g.list_assets(pid)) == 1

        # a different kind / value is a distinct asset
        _, is_new3 = await g.record_asset(pid, "subdomain", "www.acme.com")
        assert is_new3 is True
        assert len(await g.list_assets(pid)) == 2
        await g.close()

    asyncio.run(run())


def test_record_asset_merges_fingerprint_and_validates(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        pid = await _program(g)
        await g.record_asset(pid, "host", "acme.com", fingerprint={"server": "nginx"})
        merged, _ = await g.record_asset(pid, "host", "acme.com", fingerprint={"tls": "1.3"},
                                         metadata={"asn": "AS13335"})
        assert merged.fingerprint == {"server": "nginx", "tls": "1.3"}
        assert merged.metadata_json == {"asn": "AS13335"}

        with pytest.raises(ValueError, match="asset kind must be one of"):
            await g.record_asset(pid, "banana", "x.acme.com")
        with pytest.raises(ValueError, match="canonical_value is required"):
            await g.record_asset(pid, "host", "  ")
        await g.close()

    asyncio.run(run())


def test_list_assets_filters(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        pid = await _program(g)
        await g.record_asset(pid, "subdomain", "a.acme.com")
        await g.record_asset(pid, "ip", "1.2.3.4")
        dead, _ = await g.record_asset(pid, "subdomain", "old.acme.com", alive=False)
        noise, _ = await g.record_asset(pid, "subdomain", "rand.acme.com")
        # flag one asset as wildcard-DNS noise (persist through a fresh session)
        async with g._session() as s:
            fresh = await s.get(type(noise), noise.id)
            fresh.is_wildcard_noise = True
            await s.commit()

        assert len(await g.list_assets(pid)) == 3                 # noise excluded by default
        assert len(await g.list_assets(pid, include_noise=True)) == 4
        assert len(await g.list_assets(pid, kind="subdomain")) == 2  # a + old (noise excluded)
        assert len(await g.list_assets(pid, kind="ip")) == 1
        assert len(await g.list_assets(pid, alive_only=True)) == 2   # dead excluded, noise excluded
        assert dead.is_alive is False
        await g.close()

    asyncio.run(run())


def test_new_assets_since(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        pid = await _program(g)
        await g.record_asset(pid, "subdomain", "a.acme.com")
        await g.record_asset(pid, "subdomain", "b.acme.com")

        past = datetime(2000, 1, 1, tzinfo=UTC)
        future = datetime.now(UTC) + timedelta(days=1)
        assert len(await g.new_assets_since(pid, past)) == 2       # everything is "new" since 2000
        assert await g.new_assets_since(pid, future) == []         # nothing new in the future
        await g.close()

    asyncio.run(run())


def test_scan_run_lifecycle(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        pid = await _program(g)
        run = await g.start_scan_run(pid, triggered_by="cron", config={"depth": 2})
        assert run.status == "running" and run.ended_at is None

        done = await g.finish_scan_run(run.id, status="completed",
                                       stats={"assets_seen": 5, "findings_new": 1})
        assert done.status == "completed" and done.ended_at is not None
        assert done.stats["assets_seen"] == 5

        with pytest.raises(ValueError, match="status must be one of"):
            await g.finish_scan_run(run.id, status="bogus")
        assert await g.finish_scan_run("nonexistent") is None
        await g.close()

    asyncio.run(run())
