"""Tests for resumable scans: phase checkpointing, DB rehydration, and the
orchestrator's skip-completed-phases logic (`hydra scan --resume`)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from hydra.core import schemas
from hydra.core.config import ScanConfig, ScopeConfig, Settings
from hydra.core.orchestrator import Orchestrator
from hydra.db.store import Store


def _db_url(tmp_path, name: str = "h.db") -> str:
    # as_posix() keeps the SQLAlchemy URL valid on Windows (no backslashes).
    return f"sqlite+aiosqlite:///{tmp_path.as_posix()}/{name}"


def _config(scan_id: str = "s1") -> ScanConfig:
    # no_exploit + no browser keep Orchestrator.setup() free of network/callback I/O.
    return ScanConfig(
        scan_id=scan_id,
        target="http://h",
        scope=ScopeConfig(domains=["h"]),
        no_exploit=True,
        use_browser=False,
    )


async def _seed(store: Store, config: ScanConfig, *, phase: str) -> int:
    """Persist a scan with one asset, one endpoint, one finding; return finding db id."""
    await store.create_scan(
        config.scan_id,
        config.target,
        config.scope.model_dump(mode="json"),
        config.model_dump(mode="json"),
    )
    await store.add_asset(
        config.scan_id,
        schemas.Asset(fqdn="h", ips=["127.0.0.1"], ports=[80], discovery_method="seed"),
    )
    await store.add_endpoint(
        config.scan_id,
        schemas.Endpoint(
            url="http://h/a",
            method=schemas.HttpMethod.POST,
            params=[schemas.Param(name="q", location=schemas.ParamLocation.QUERY)],
        ),
    )
    fid = await store.add_finding(
        config.scan_id,
        schemas.Finding(
            vuln_type="xss",
            title="reflected",
            severity=schemas.Severity.HIGH,
            url="http://h/a",
            parameter="q",
            param_location=schemas.ParamLocation.QUERY,
            evidence=schemas.Evidence(matched_at="<script>"),
        ),
    )
    await store.set_scan_phase(config.scan_id, phase)
    return fid


# --------------------------------------------------------- pure phase ordering
def test_phase_complete_ordering():
    orch = Orchestrator(_config(), Settings())
    assert orch._phase_complete("recon") is False  # fresh scan: nothing completed
    orch._resume_phase = "scan"
    assert orch._phase_complete("recon") is True
    assert orch._phase_complete("scan") is True
    assert orch._phase_complete("exploit") is False  # not reached yet
    orch._resume_phase = "exploit"
    assert orch._phase_complete("exploit") is True


# --------------------------------------------------------------- store helpers
async def test_set_and_get_scan_phase(tmp_path):
    store = Store(_db_url(tmp_path))
    await store.init()
    config = _config()
    await store.create_scan(config.scan_id, config.target, {}, {})
    assert (await store.get_scan(config.scan_id)).phase is None
    await store.set_scan_phase(config.scan_id, "recon")
    assert (await store.get_scan(config.scan_id)).phase == "recon"
    await store.close()


async def test_rehydrate_assets_endpoints_findings(tmp_path):
    store = Store(_db_url(tmp_path))
    await store.init()
    config = _config()
    fid = await _seed(store, config, phase="scan")

    assets = await store.get_assets(config.scan_id)
    assert len(assets) == 1
    assert isinstance(assets[0], schemas.Asset)
    assert assets[0].fqdn == "h" and assets[0].ports == [80]

    endpoints = await store.get_endpoints(config.scan_id)
    assert len(endpoints) == 1
    assert endpoints[0].method == schemas.HttpMethod.POST
    assert endpoints[0].params[0].name == "q"  # JSON column round-tripped to a Param

    findings = await store.get_findings_with_ids(config.scan_id)
    assert len(findings) == 1
    db_id, finding = findings[0]
    assert db_id == fid  # DB id preserved so exploit phase can attach to the row
    assert finding.severity == schemas.Severity.HIGH
    assert finding.evidence.matched_at == "<script>"
    await store.close()


async def test_init_adds_phase_column_to_legacy_db(tmp_path):
    """A DB created before the resume feature lacks scans.phase; init() adds it."""
    db_url = _db_url(tmp_path, "legacy.db")
    engine = create_async_engine(db_url)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "CREATE TABLE scans (id VARCHAR(64) PRIMARY KEY, target TEXT, "
                "scope_json JSON, config_json JSON, status VARCHAR(32), "
                "started_at DATETIME, completed_at DATETIME)"
            )
        )
    await engine.dispose()

    store = Store(db_url)
    await store.init()  # create_all skips the existing table; migration adds phase
    await store.create_scan("s1", "http://h", {}, {})
    await store.set_scan_phase("s1", "scan")
    assert (await store.get_scan("s1")).phase == "scan"
    await store.close()


# ----------------------------------------------------- orchestrator resume flow
async def test_resume_skips_completed_phases(tmp_path, monkeypatch):
    """phase='scan' => recon and scan are skipped; persisted findings are reused
    and the scanner registry is never consulted."""
    db_url = _db_url(tmp_path)
    config = _config()
    seed = Store(db_url)
    await seed.init()
    fid = await _seed(seed, config, phase="scan")
    await seed.close()

    def _boom(_modules):
        raise AssertionError("get_scanners must not run for an already-completed scan phase")

    monkeypatch.setattr("hydra.core.orchestrator.get_scanners", _boom)

    orch = Orchestrator(config, Settings(db_url=db_url), resume=True)
    await orch.setup()
    try:
        assert orch._resume_phase == "scan"
        assert len(orch.ctx.assets) == 1
        assert len(orch.ctx.endpoints) == 1
        assert orch.ctx.finding_ids[orch.ctx.findings[0].id] == fid

        orch.ctx.baseline = SimpleNamespace()  # non-None => recon skip won't probe the network
        assert await orch.run_recon() == (1, 1)  # assets, endpoints reused
        assert await orch.run_scan() == 1  # finding reused; _boom proves scanners didn't run
    finally:
        await orch.teardown("completed")


async def test_resume_runs_remaining_phase(tmp_path, monkeypatch):
    """phase='recon' => recon is skipped but scan still runs and re-checkpoints."""
    db_url = _db_url(tmp_path)
    config = _config()
    seed = Store(db_url)
    await seed.init()
    await _seed(seed, config, phase="recon")
    await seed.close()

    monkeypatch.setattr("hydra.core.orchestrator.get_scanners", lambda _modules: [])

    orch = Orchestrator(config, Settings(db_url=db_url), resume=True)
    await orch.setup()
    try:
        assert orch._resume_phase == "recon"
        orch.ctx.baseline = SimpleNamespace()
        assert await orch.run_recon() == (1, 1)  # recon skipped, inventory reused
        await orch.run_scan()  # no scanners registered -> completes immediately
        # the scan phase advanced the checkpoint
        assert (await orch.store.get_scan(config.scan_id)).phase == "scan"
    finally:
        await orch.teardown("completed")


async def test_resume_missing_scan_raises(tmp_path):
    orch = Orchestrator(_config("ghost"), Settings(db_url=_db_url(tmp_path)), resume=True)
    with pytest.raises(ValueError, match="cannot resume"):
        await orch.setup()
    await orch.store.close()


# ------------------------------------------------------- scan listing (hydra scans)
async def test_list_scans_orders_and_counts(tmp_path):
    store = Store(_db_url(tmp_path))
    await store.init()
    # Two scans: one with a finding, one without.
    cfg_a = _config("a")
    await _seed(store, cfg_a, phase="scan")  # adds 1 finding
    await store.create_scan("b", "http://h", {}, {})  # no findings
    await store.set_scan_status("b", "completed", completed=True)

    listed = await store.list_scans()
    ids = {row.id: count for row, count in listed}
    assert ids == {"a": 1, "b": 0}  # counts include scans with zero findings

    # status filter narrows the result set.
    await store.set_scan_status("a", "failed")
    failed = await store.list_scans(status="failed")
    assert [row.id for row, _ in failed] == ["a"]
    assert (await store.list_scans(status="running")) == []
    await store.close()


async def test_list_scans_respects_limit(tmp_path):
    store = Store(_db_url(tmp_path))
    await store.init()
    for i in range(5):
        await store.create_scan(f"s{i}", "http://h", {}, {})
    assert len(await store.list_scans(limit=3)) == 3
    await store.close()
