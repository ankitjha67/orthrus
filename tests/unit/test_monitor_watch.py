"""`orthrus monitor --watch`: the continuous-loop driver bounds + chains runs."""

from __future__ import annotations

import orthrus.main as m
from orthrus.core.config import ScanConfig, ScopeConfig


async def test_watch_bounds_runs_and_chains_baseline(monkeypatch):
    calls = []

    async def fake_monitor(config, baseline_id, webhook, deep, no_host_gather, as_json):
        calls.append({"scan_id": config.scan_id, "baseline_id": baseline_id})
        return False

    monkeypatch.setattr(m, "_monitor", fake_monitor)
    cfg = ScanConfig(target="https://x.test/", scope=ScopeConfig(domains=["x.test"]))

    await m._watch_monitor(
        cfg, "explicit-base", None, False, True, False, interval=0, max_runs=3
    )

    # --max-runs bounds the loop
    assert len(calls) == 3
    # the explicit baseline applies only to the first pass; later passes auto-chain
    assert calls[0]["baseline_id"] == "explicit-base"
    assert calls[1]["baseline_id"] is None and calls[2]["baseline_id"] is None
    # each pass takes a fresh (auto-generated) snapshot id
    assert all(c["scan_id"] is None for c in calls)


async def test_monitor_batch_runs_each_target_and_summarises(monkeypatch):
    from orthrus.main import console

    calls = []

    async def fake_monitor(config, baseline, webhook, deep, no_host_gather, as_json):
        calls.append(config.target)
        return config.target == "https://b.test/"  # only b drifts

    monkeypatch.setattr(m, "_monitor", fake_monitor)
    with console.capture() as cap:
        changed = await m._monitor_batch(
            ["https://a.test/", "https://b.test/"], None, None, False, True, None, 50.0, 30.0
        )
    out = cap.get()

    assert calls == ["https://a.test/", "https://b.test/"]   # each target monitored
    assert changed is True                                    # at least one drifted
    assert "2 target(s) monitored" in out and "1 with drift" in out
    assert "drift" in out and "no change" in out


async def test_monitor_batch_no_drift_returns_false(monkeypatch):
    async def fake_monitor(config, baseline, webhook, deep, no_host_gather, as_json):
        return False

    monkeypatch.setattr(m, "_monitor", fake_monitor)
    from orthrus.main import console

    with console.capture():
        changed = await m._monitor_batch(
            ["https://a.test/", "https://b.test/"], None, None, False, True, None, 50.0, 30.0
        )
    assert changed is False


async def test_watch_passes_through_deep_and_webhook(monkeypatch):
    seen = {}

    async def fake_monitor(config, baseline_id, webhook, deep, no_host_gather, as_json):
        seen.update(webhook=webhook, deep=deep, no_host_gather=no_host_gather)
        return False

    monkeypatch.setattr(m, "_monitor", fake_monitor)
    cfg = ScanConfig(target="https://x.test/", scope=ScopeConfig(domains=["x.test"]))

    await m._watch_monitor(
        cfg, None, "https://hook.test/x", True, False, False, interval=0, max_runs=1
    )
    assert seen == {"webhook": "https://hook.test/x", "deep": True, "no_host_gather": False}
