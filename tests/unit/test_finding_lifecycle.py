"""Finding triage lifecycle: status + ownership (`orthrus finding …`)."""

from __future__ import annotations

import asyncio
import json

from click.testing import CliRunner

from orthrus import main
from orthrus.core.schemas import FINDING_STATUSES, Finding, Severity
from orthrus.db.store import Store


def _db_url(tmp_path) -> str:
    return f"sqlite+aiosqlite:///{(tmp_path / 'h.db').as_posix()}"


async def _seed(db_url: str) -> int:
    store = Store(db_url)
    await store.init()
    await store.create_scan("s", "http://t", {}, {})
    fid = await store.add_finding(
        "s",
        Finding(vuln_type="sqli", title="SQL injection", severity=Severity.CRITICAL, url="http://t/q"),
    )
    await store.close()
    return fid


def test_default_status_is_open_and_no_owner():
    f = Finding(vuln_type="xss", title="t", severity=Severity.LOW, url="http://t")
    assert f.status == "open"
    assert f.owner is None


def test_finding_statuses_catalog():
    assert "open" in FINDING_STATUSES
    assert "false-positive" in FINDING_STATUSES
    assert "resolved" in FINDING_STATUSES


def test_store_set_status_and_owner_roundtrip(tmp_path):
    db_url = _db_url(tmp_path)
    fid = asyncio.run(_seed(db_url))

    async def run():
        store = Store(db_url)
        await store.init()
        assert await store.set_finding_status(fid, "resolved") is True
        assert await store.set_finding_owner(fid, "alice") is True
        rows = await store.get_findings("s")
        await store.close()
        return rows

    rows = asyncio.run(run())
    assert rows[0].status == "resolved"
    assert rows[0].owner == "alice"


def test_store_update_unknown_id_returns_false(tmp_path):
    db_url = _db_url(tmp_path)
    asyncio.run(_seed(db_url))

    async def run():
        store = Store(db_url)
        await store.init()
        r1 = await store.set_finding_status(9999, "triaged")
        r2 = await store.set_finding_owner(9999, "bob")
        await store.close()
        return r1, r2

    assert asyncio.run(run()) == (False, False)


def test_cli_set_status_then_shows_in_findings_json(tmp_path, monkeypatch):
    db_url = _db_url(tmp_path)
    fid = asyncio.run(_seed(db_url))
    monkeypatch.setenv("ORTHRUS_DB_URL", db_url)

    r = CliRunner().invoke(main.cli, ["--no-banner", "finding", "status", str(fid), "triaged"])
    assert r.exit_code == 0, r.output

    r = CliRunner().invoke(main.cli, ["--no-banner", "findings", "--scan-id", "s", "--json"])
    data = json.loads(r.output)
    assert data[0]["id"] == fid
    assert data[0]["status"] == "triaged"


def test_cli_assign_and_clear_owner(tmp_path, monkeypatch):
    db_url = _db_url(tmp_path)
    fid = asyncio.run(_seed(db_url))
    monkeypatch.setenv("ORTHRUS_DB_URL", db_url)

    CliRunner().invoke(main.cli, ["--no-banner", "finding", "assign", str(fid), "carol"])
    data = json.loads(
        CliRunner().invoke(main.cli, ["--no-banner", "findings", "--scan-id", "s", "--json"]).output
    )
    assert data[0]["owner"] == "carol"

    # '-' clears the assignment.
    CliRunner().invoke(main.cli, ["--no-banner", "finding", "assign", str(fid), "-"])
    data = json.loads(
        CliRunner().invoke(main.cli, ["--no-banner", "findings", "--scan-id", "s", "--json"]).output
    )
    assert data[0]["owner"] is None


def test_cli_rejects_invalid_status(tmp_path, monkeypatch):
    db_url = _db_url(tmp_path)
    fid = asyncio.run(_seed(db_url))
    monkeypatch.setenv("ORTHRUS_DB_URL", db_url)
    r = CliRunner().invoke(main.cli, ["--no-banner", "finding", "status", str(fid), "not-a-status"])
    assert r.exit_code != 0  # click.Choice rejects it
