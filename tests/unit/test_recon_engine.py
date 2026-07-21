"""Recon engine (PRD §7.2): adapter run → graph fold, dedup, wildcard, diff."""

from __future__ import annotations

import asyncio

from orthrus.model.store import ProgramGraph
from orthrus.recon_engine import (
    DiscoveredAsset,
    ReconAdapter,
    ReconEngine,
    ReconScope,
    get_recon_adapters,
    register_recon,
)


def _graph(tmp_path) -> ProgramGraph:
    return ProgramGraph(f"sqlite+aiosqlite:///{(tmp_path / 'recon.db').as_posix()}")


def _resolver(mapping: dict[str, list[str]]):
    async def resolve(name: str) -> list[str]:
        return list(mapping.get(name, []))
    return resolve


class _Fake(ReconAdapter):
    name = "fake"

    def __init__(self, assets):
        self._assets = assets

    async def discover(self, scope: ReconScope):
        return list(self._assets)


class _Boom(ReconAdapter):
    name = "boom"

    async def discover(self, scope: ReconScope):
        raise RuntimeError("source down")


class _NeedsBinary(ReconAdapter):
    name = "needs-binary"
    binary = "definitely-not-installed-xyz"

    async def discover(self, scope: ReconScope):
        return [DiscoveredAsset("subdomain", "should-not-run.acme.com", "needs-binary")]


def test_engine_records_dedups_and_diffs(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        pid = (await g.create_program("Acme", "self-owned-lab", platform="self")).id
        adapter = _Fake([
            DiscoveredAsset("subdomain", "API.acme.com", "fake"),
            DiscoveredAsset("subdomain", "api.acme.com.", "fake"),   # dup after canonicalization
            DiscoveredAsset("subdomain", "www.acme.com", "fake"),
        ])
        engine = ReconEngine(g, [adapter], resolve=_resolver({}))   # no wildcard
        res = await engine.run(pid, ReconScope(domains=["acme.com"]))
        assert res.discovered == 3 and res.recorded == 2            # canonical dedup
        assert sorted(res.new) == ["api.acme.com", "www.acme.com"]

        # second run: nothing new (identity dedup in the graph)
        res2 = await engine.run(pid, ReconScope(domains=["acme.com"]))
        assert res2.new == [] and res2.recorded == 2
        await g.close()

    asyncio.run(run())


def test_engine_flags_wildcard_noise(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        pid = (await g.create_program("Acme", "self-owned-lab", platform="self")).id
        # a wildcard zone: every random probe + the junk host resolve to the same IP
        wild_ip = ["9.9.9.9"]
        mapping = {
            "orthrus-nx-a1b2c3.acme.com": wild_ip,
            "zzq-does-not-exist-9182.acme.com": wild_ip,
            "no-such-host-4471.acme.com": wild_ip,
            "junk.acme.com": wild_ip,          # only the wildcard IP → noise
            "real.acme.com": ["1.2.3.4"],      # a distinct IP → genuine
        }
        engine = ReconEngine(g, [_Fake([
            DiscoveredAsset("subdomain", "real.acme.com", "fake"),
            DiscoveredAsset("subdomain", "junk.acme.com", "fake"),
        ])], resolve=_resolver(mapping))
        res = await engine.run(pid, ReconScope(domains=["acme.com"]))
        assert res.new == ["real.acme.com"] and res.wildcard_noise == 1
        # noise is stored but hidden from the default asset list
        assert len(await g.list_assets(pid)) == 1
        assert len(await g.list_assets(pid, include_noise=True)) == 2
        await g.close()

    asyncio.run(run())


def test_engine_survives_failing_and_unavailable_sources(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        pid = (await g.create_program("Acme", "self-owned-lab", platform="self")).id
        engine = ReconEngine(
            g,
            [_Fake([DiscoveredAsset("subdomain", "a.acme.com", "fake")]), _Boom(), _NeedsBinary()],
            resolve=_resolver({}),
        )
        res = await engine.run(pid, ReconScope(domains=["acme.com"]))
        assert res.new == ["a.acme.com"]              # fake succeeded
        assert res.failed_sources == ["boom"]          # boom caught, didn't kill the run
        assert "needs-binary" not in res.sources_run   # unavailable binary skipped
        await g.close()

    asyncio.run(run())


def test_recon_registry():
    @register_recon
    class _Reg(ReconAdapter):
        name = "reg-test"

        async def discover(self, scope):
            return []

    names = {a.name for a in get_recon_adapters(["reg-test"])}
    assert "reg-test" in names
    assert get_recon_adapters(["nonexistent"]) == []
