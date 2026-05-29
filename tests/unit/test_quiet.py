"""--quiet: suppress phase chrome + per-module chatter, show only banner/results.

Covers both halves of the feature: the orchestrator gates its phase dividers on
``config.quiet``, and the CLI forces a warning-level log so info chatter is
silenced while warnings/errors (scope blocks, auth failures, the --fail-on gate)
still surface.
"""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from orthrus import main
from orthrus.core.config import ScanConfig, ScopeConfig, Settings
from orthrus.core.orchestrator import Orchestrator


def _make_orch(*, quiet: bool) -> Orchestrator:
    config = ScanConfig(
        target="http://t.example/",
        scope=ScopeConfig(domains=["t.example"]),
        quiet=quiet,
    )
    return Orchestrator(config, Settings(db_url="sqlite+aiosqlite:///:memory:"))


def test_section_suppressed_when_quiet():
    orch = _make_orch(quiet=True)
    with patch("orthrus.core.orchestrator.section") as sect:
        orch._section("PHASE · RECON")
    sect.assert_not_called()


def test_section_printed_when_not_quiet():
    orch = _make_orch(quiet=False)
    with patch("orthrus.core.orchestrator.section") as sect:
        orch._section("PHASE · RECON")
    sect.assert_called_once()


# Replace the async _run_scan with a plain stub (returns the tally directly) so
# the CLI never builds a real coroutine and no event loop runs.
def _stub_run_scan(_config, **_kw):
    return {}


def test_quiet_flag_forces_warning_log_level():
    runner = CliRunner()
    with (
        patch.object(main, "configure_logging") as cfg_log,
        patch.object(main, "_run_scan", new=_stub_run_scan),
        patch.object(main.asyncio, "run", return_value={}),
    ):
        result = runner.invoke(
            main.cli, ["--no-banner", "scan", "-t", "http://t.example/", "--quiet"]
        )
    assert result.exit_code == 0, result.output
    cfg_log.assert_called_once_with("warning")


def test_without_quiet_uses_requested_verbosity():
    runner = CliRunner()
    with (
        patch.object(main, "configure_logging") as cfg_log,
        patch.object(main, "_run_scan", new=_stub_run_scan),
        patch.object(main.asyncio, "run", return_value={}),
    ):
        result = runner.invoke(
            main.cli, ["--no-banner", "scan", "-t", "http://t.example/", "-v", "debug"]
        )
    assert result.exit_code == 0, result.output
    cfg_log.assert_called_once_with("debug")
