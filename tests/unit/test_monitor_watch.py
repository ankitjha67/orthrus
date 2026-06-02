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
