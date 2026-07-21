"""`orthrus program-scan` guard paths (no network - no live assets to scan)."""

from __future__ import annotations

import asyncio

from click.testing import CliRunner

import orthrus.main as main
from orthrus.model.store import ProgramGraph


def test_program_scan_unknown_program_errors(tmp_path, monkeypatch):
    monkeypatch.setenv("ORTHRUS_DB_URL", f"sqlite+aiosqlite:///{(tmp_path / 's.db').as_posix()}")
    r = CliRunner().invoke(main.cli, ["--no-banner", "program-scan", "--program", "nope"])
    assert r.exit_code != 0 and "no program" in r.output.lower()


def test_program_scan_no_assets_is_clean_noop(tmp_path, monkeypatch):
    db = f"sqlite+aiosqlite:///{(tmp_path / 's.db').as_posix()}"
    monkeypatch.setenv("ORTHRUS_DB_URL", db)

    async def seed():
        g = ProgramGraph(db)
        await g.init()
        await g.create_program("lab", "self-owned-lab", platform="self")  # no assets discovered yet
        await g.close()

    asyncio.run(seed())
    r = CliRunner().invoke(main.cli, ["--no-banner", "program-scan", "--program", "lab"])
    assert r.exit_code == 0, r.output
    assert "no live in-scope assets" in r.output   # nothing scanned, no network
