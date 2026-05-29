"""`hydra scan --dry-run`: resolve scope + scanner plan, send zero packets.

Two halves: the pure ``_resolve_plan`` partitioning (modules selection +
aggressiveness gate) and the CLI guarantee that --dry-run never executes the
scan (the load-bearing safety property — no request leaves the host).
"""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from hydra import main
from hydra.core.config import ScanConfig, ScopeConfig
from hydra.core.schemas import Aggressiveness


def test_resolve_plan_all_aggressive_runs_everything():
    plan = main._resolve_plan(["all"], Aggressiveness.AGGRESSIVE)
    assert plan["gated"] == []  # aggressive is the highest tier; nothing is gated
    assert len(plan["will_run"]) >= 20


def test_resolve_plan_normal_partitions_same_total_set():
    aggressive = main._resolve_plan(["all"], Aggressiveness.AGGRESSIVE)
    normal = main._resolve_plan(["all"], Aggressiveness.NORMAL)
    # Same universe of modules, just split differently by the aggressiveness gate.
    assert set(normal["will_run"]) | set(normal["gated"]) == set(aggressive["will_run"])
    # Everything that runs at NORMAL is a subset of what runs at AGGRESSIVE.
    assert set(normal["will_run"]) <= set(aggressive["will_run"])


def test_resolve_plan_module_selection_narrows():
    plan = main._resolve_plan(["sqli"], Aggressiveness.AGGRESSIVE)
    assert "sqli" in plan["will_run"]
    # A single-module selection is far smaller than the full suite.
    assert len(plan["will_run"]) + len(plan["gated"]) < 20


def test_dry_run_plan_escapes_bracketed_target():
    # A target with bracketed query text must render literally, not be swallowed
    # by Rich as a markup tag.
    from hydra.utils.logger import console

    config = ScanConfig(
        target="http://t.example/?f=[active]",
        scope=ScopeConfig(domains=["t.example"]),
        modules=["sqli"],
    )
    with console.capture() as cap:
        main._print_scan_plan(config)
    out = cap.get()
    assert "[active]" in out  # preserved verbatim
    assert "sqli" in out  # the resolved plan rendered


def test_dry_run_does_not_execute_scan():
    runner = CliRunner()
    with patch.object(main.asyncio, "run") as run_mock:
        result = runner.invoke(
            main.cli, ["--no-banner", "scan", "-t", "http://t.example/", "--dry-run"]
        )
    assert result.exit_code == 0, result.output
    run_mock.assert_not_called()  # no event loop -> no network


# Plain (non-coroutine) stub so patching asyncio.run never leaves an unawaited
# coroutine; mirrors the approach in test_quiet.py.
def _stub_run_scan(_config, **_kw):
    return {}


def test_normal_scan_still_executes():
    """Sanity counterpart: without --dry-run the scan path does run the loop."""
    runner = CliRunner()
    with (
        patch.object(main, "_run_scan", new=_stub_run_scan),
        patch.object(main.asyncio, "run", return_value={}) as run_mock,
    ):
        result = runner.invoke(
            main.cli, ["--no-banner", "scan", "-t", "http://t.example/", "--no-exploit"]
        )
    assert result.exit_code == 0, result.output
    run_mock.assert_called_once()
