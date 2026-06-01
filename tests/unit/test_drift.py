"""Attack-surface drift engine + store prior-scan baseline lookup."""

from __future__ import annotations

from orthrus.core.drift import compute_asset_drift
from orthrus.core.schemas import Asset
from orthrus.db.store import Store


# ------------------------------------------------------------- drift engine
def test_baseline_run_records_without_new_noise():
    cur = [Asset(fqdn="a.com"), Asset(fqdn="b.com")]
    d = compute_asset_drift([], cur)
    assert d.is_baseline and not d.has_changes
    assert d.new_hosts == [] and d.current_count == 2
    assert "baseline established" in d.summary()


def test_new_and_removed_hosts():
    base = [Asset(fqdn="keep.com"), Asset(fqdn="gone.com")]
    cur = [Asset(fqdn="keep.com"), Asset(fqdn="fresh.com")]
    d = compute_asset_drift(base, cur)
    assert [a.fqdn for a in d.new_hosts] == ["fresh.com"]
    assert d.removed_hosts == ["gone.com"]
    assert d.unchanged == 1
    assert d.has_changes


def test_changed_host_new_ips_and_ports():
    base = [Asset(fqdn="x.com", ips=["1.1.1.1"], ports=[80])]
    cur = [Asset(fqdn="x.com", ips=["1.1.1.1", "2.2.2.2"], ports=[80, 443])]
    d = compute_asset_drift(base, cur)
    assert len(d.changed_hosts) == 1
    ch = d.changed_hosts[0]
    assert ch.new_ips == ["2.2.2.2"] and ch.new_ports == [443]
    assert ch.removed_ips == [] and ch.removed_ports == []


def test_changed_host_removed_ips_and_ports():
    base = [Asset(fqdn="x.com", ips=["1.1.1.1", "2.2.2.2"], ports=[80, 443])]
    cur = [Asset(fqdn="x.com", ips=["1.1.1.1"], ports=[80])]
    ch = compute_asset_drift(base, cur).changed_hosts[0]
    assert ch.removed_ips == ["2.2.2.2"] and ch.removed_ports == [443]


def test_no_drift_when_identical():
    base = [Asset(fqdn="x.com", ips=["1.1.1.1"], ports=[80])]
    cur = [Asset(fqdn="x.com", ips=["1.1.1.1"], ports=[80])]
    d = compute_asset_drift(base, cur)
    assert not d.has_changes and d.unchanged == 1
    assert "no drift" in d.summary()


def test_to_dict_shape_for_alerts():
    base = [Asset(fqdn="x.com")]
    cur = [Asset(fqdn="x.com"), Asset(fqdn="y.com", ips=["9.9.9.9"])]
    out = compute_asset_drift(base, cur).to_dict()
    assert out["has_changes"] is True
    assert out["new_hosts"][0]["fqdn"] == "y.com"
    assert out["new_hosts"][0]["ips"] == ["9.9.9.9"]


def test_explicit_is_baseline_suppresses_diff():
    base = [Asset(fqdn="x.com")]
    cur = [Asset(fqdn="y.com")]
    d = compute_asset_drift(base, cur, is_baseline=True)
    assert d.is_baseline and not d.has_changes


# ------------------------------------------------ store prior-scan baseline
async def test_get_prior_scan_returns_latest_completed_for_target():
    store = Store("sqlite+aiosqlite:///:memory:")
    await store.init()
    try:
        await store.create_scan("s1", "https://t.example/", {}, {})
        await store.set_scan_status("s1", "completed")
        await store.create_scan("s2", "https://t.example/", {}, {})
        await store.set_scan_status("s2", "completed")
        await store.create_scan("s3", "https://other.example/", {}, {})
        await store.set_scan_status("s3", "completed")

        # Current run is a different id → newest completed for the target is s2.
        prior = await store.get_prior_scan("https://t.example/", exclude_id="s4")
        assert prior is not None and prior.id == "s2"
        # Excluding s2 falls back to s1.
        prior2 = await store.get_prior_scan("https://t.example/", exclude_id="s2")
        assert prior2 is not None and prior2.id == "s1"
        # A target with no completed scan has no baseline.
        assert await store.get_prior_scan("https://unseen.example/") is None
    finally:
        await store.close()


async def test_get_prior_scan_ignores_non_completed():
    store = Store("sqlite+aiosqlite:///:memory:")
    await store.init()
    try:
        await store.create_scan("r1", "https://t2.example/", {}, {})
        # left in default 'pending'/'running' state — not a valid baseline
        assert await store.get_prior_scan("https://t2.example/") is None
    finally:
        await store.close()
