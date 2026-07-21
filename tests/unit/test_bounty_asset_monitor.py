"""Cross-run asset monitor - new/removed in-scope host detection."""

from __future__ import annotations

from orthrus.bounty.asset_monitor import AssetMonitor


def test_first_run_is_baseline(tmp_path):
    mon = AssetMonitor(tmp_path / "snap.json")
    diff = mon.record("acme", ["a.acme.com", "b.acme.com"])
    assert diff.is_first is True
    assert diff.added == ["a.acme.com", "b.acme.com"]
    assert diff.removed == []
    assert diff.total == 2
    assert "baseline" in diff.summary()


def test_second_run_detects_new_and_removed(tmp_path):
    mon = AssetMonitor(tmp_path / "snap.json")
    mon.record("acme", ["a.acme.com", "b.acme.com"])
    diff = mon.record("acme", ["b.acme.com", "c.acme.com", "d.acme.com"])
    assert diff.is_first is False
    assert diff.added == ["c.acme.com", "d.acme.com"]   # new surface
    assert diff.removed == ["a.acme.com"]                # gone
    assert diff.has_changes is True
    assert diff.total == 3


def test_normalizes_and_dedupes(tmp_path):
    mon = AssetMonitor(tmp_path / "snap.json")
    diff = mon.record("acme", ["A.Acme.com", "a.acme.com.", " b.acme.com ", ""])
    assert diff.added == ["a.acme.com", "b.acme.com"]    # case/trailing-dot/blank folded
    assert mon.latest("acme") == ["a.acme.com", "b.acme.com"]


def test_no_change_run(tmp_path):
    mon = AssetMonitor(tmp_path / "snap.json")
    mon.record("acme", ["a.acme.com"])
    diff = mon.record("acme", ["a.acme.com"])
    assert diff.has_changes is False
    assert "no change" in diff.summary()


def test_programs_are_isolated(tmp_path):
    mon = AssetMonitor(tmp_path / "snap.json")
    mon.record("acme", ["a.acme.com"])
    diff = mon.record("beta", ["x.beta.com"])
    assert diff.is_first is True                          # beta has its own baseline
    assert mon.latest("acme") == ["a.acme.com"]
    assert mon.latest("beta") == ["x.beta.com"]
    assert mon.latest("nobody") == []
