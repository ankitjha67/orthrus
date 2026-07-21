"""Shared recon pass (recon_once) + the `orthrus recon-watch` loop."""

from __future__ import annotations

import asyncio

from orthrus.model.store import ProgramGraph
from orthrus.recon_engine import DiscoveredAsset, ReconAdapter, register_recon
from orthrus.recon_engine.run import recon_once


@register_recon
class _OnceFake(ReconAdapter):
    name = "once-fake"

    async def discover(self, scope):
        return [DiscoveredAsset("subdomain", "new.acme.com", "once-fake")]


async def _no_resolve(name):   # keep wildcard detection offline
    return []


def test_recon_once_records_and_notifies(tmp_path, monkeypatch):
    monkeypatch.setattr("orthrus.recon_engine.engine._default_resolve", _no_resolve)
    sent: dict[str, object] = {}

    async def fake_slack(url, payload):
        sent["slack"] = payload
        return True

    async def fake_discord(url, content):
        sent["discord"] = content
        return True

    monkeypatch.setattr("orthrus.integrations.notify.send_slack", fake_slack)
    monkeypatch.setattr("orthrus.integrations.notify.send_discord", fake_discord)

    async def run():
        g = ProgramGraph(f"sqlite+aiosqlite:///{(tmp_path / 'once.db').as_posix()}")
        await g.init()
        pid = (await g.create_program("Acme", "self-owned-lab", platform="self")).id
        result, notified = await recon_once(
            g, pid, "Acme", ["acme.com"], sources="once-fake",
            notify_slack="http://s", notify_discord="http://d")
        assert result.new == ["new.acme.com"]
        assert notified == {"slack": True, "discord": True}
        assert "new.acme.com" in sent["slack"]["text"] and "new.acme.com" in sent["discord"]
        # audit-logged
        ok, _ = await g.verify_audit()
        assert ok is True
        await g.close()

    asyncio.run(run())


def test_recon_watch_bounded_run(tmp_path, monkeypatch):
    from click.testing import CliRunner

    import orthrus.main as main

    monkeypatch.setattr("orthrus.recon_engine.engine._default_resolve", _no_resolve)
    db = f"sqlite+aiosqlite:///{(tmp_path / 'watch.db').as_posix()}"
    monkeypatch.setenv("ORTHRUS_DB_URL", db)

    async def seed():
        g = ProgramGraph(db)
        await g.init()
        p = await g.create_program("lab", "self-owned-lab", platform="self")
        await g.add_scope_entry(p.id, "lab.test", entry_type="in", kind="domain")
        await g.close()

    asyncio.run(seed())

    r = CliRunner().invoke(main.cli, [
        "--no-banner", "recon-watch", "--program", "lab",
        "--max-runs", "1", "--interval", "0", "--sources", "subfinder",
    ])
    assert r.exit_code == 0, r.output
    assert "pass 1:" in r.output and "1 pass(es)" in r.output

    # unknown program errors cleanly
    r2 = CliRunner().invoke(main.cli, ["--no-banner", "recon-watch", "--program", "nope", "--max-runs", "1"])
    assert r2.exit_code != 0 and "no program" in r2.output.lower()
