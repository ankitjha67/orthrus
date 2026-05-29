"""`hydra scan --target-file`: local sequential batch scanning.

Two halves: the pure file/path helpers (target parsing, per-target report
naming) and the CLI guarantees — each target becomes its own scan with its own
auto-derived scope, batch --dry-run sends nothing, and --target-file is
mutually exclusive with --target / --distributed.
"""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from hydra import main
from hydra.core.config import ScanConfig, ScopeConfig


def test_read_targets_skips_comments_and_blanks(tmp_path):
    p = tmp_path / "targets.txt"
    p.write_text(
        "# a comment\n"
        "http://a.example/\n"
        "\n"
        "   http://b.example/   \n"
        "# trailing comment\n",
        encoding="utf-8",
    )
    assert main._read_targets(str(p)) == ["http://a.example/", "http://b.example/"]


def test_batch_output_appends_host_slug():
    assert main._batch_output("hydra_report", "http://t.example/x?y=1") == "hydra_report_t.example"
    assert main._batch_output("out", "10.0.0.5:8080") == "out_10.0.0.5"
    # Stdout is preserved untouched (the operator owns the concatenation).
    assert main._batch_output("-", "http://t.example/") == "-"


def test_batch_dry_run_sends_nothing(tmp_path):
    p = tmp_path / "targets.txt"
    p.write_text("http://a.example/\nhttp://b.example/\n", encoding="utf-8")
    with patch.object(main.asyncio, "run") as run_mock:
        result = CliRunner().invoke(
            main.cli, ["--no-banner", "scan", "--target-file", str(p), "--dry-run"]
        )
    assert result.exit_code == 0, result.output
    run_mock.assert_not_called()  # no event loop -> no network, for every target


def _record_run_scan(seen):
    def rec(cfg, **_kw):
        seen.append(cfg)
        return {}

    return rec


def test_batch_runs_each_target_with_own_scope_and_report(tmp_path):
    p = tmp_path / "targets.txt"
    p.write_text("http://a.example/\nhttp://b.example/\n", encoding="utf-8")
    seen: list = []
    with (
        patch.object(main, "_run_scan", new=_record_run_scan(seen)),
        patch.object(main.asyncio, "run", return_value={}),
    ):
        result = CliRunner().invoke(
            main.cli, ["--no-banner", "scan", "--target-file", str(p), "--no-exploit"]
        )
    assert result.exit_code == 0, result.output
    assert [c.target for c in seen] == ["http://a.example/", "http://b.example/"]
    # Each target is its own scan (no shared id) with a distinct report path.
    assert all(c.scan_id is None for c in seen)
    assert [c.output for c in seen] == ["hydra_report_a.example", "hydra_report_b.example"]
    # Per-target scope: each scope is derived from its own host, not shared.
    assert "a.example" in seen[0].scope.domains
    assert "b.example" in seen[1].scope.domains
    assert seen[0].scope.domains != seen[1].scope.domains


def test_target_and_target_file_are_mutually_exclusive(tmp_path):
    p = tmp_path / "targets.txt"
    p.write_text("http://a.example/\n", encoding="utf-8")
    result = CliRunner().invoke(
        main.cli,
        ["--no-banner", "scan", "-t", "http://x.example/", "--target-file", str(p)],
    )
    assert result.exit_code != 0
    assert "not both" in result.output


def test_target_file_rejected_in_distributed_mode(tmp_path):
    p = tmp_path / "targets.txt"
    p.write_text("http://a.example/\n", encoding="utf-8")
    result = CliRunner().invoke(
        main.cli, ["--no-banner", "scan", "--target-file", str(p), "--distributed"]
    )
    assert result.exit_code != 0
    assert "--target-file" in result.output


def test_empty_target_file_errors(tmp_path):
    p = tmp_path / "targets.txt"
    p.write_text("# only comments\n\n", encoding="utf-8")
    with patch.object(main.asyncio, "run") as run_mock:
        result = CliRunner().invoke(
            main.cli, ["--no-banner", "scan", "--target-file", str(p)]
        )
    assert result.exit_code != 0
    assert "no targets" in result.output
    run_mock.assert_not_called()


def test_neither_target_nor_file_errors():
    result = CliRunner().invoke(main.cli, ["--no-banner", "scan"])
    assert result.exit_code != 0
    assert "--target" in result.output


def test_batch_summary_rolls_up_per_target(tmp_path):
    # A pass-through asyncio.run returns _run_scan's value unchanged, so the
    # per-target counts flow into the roll-up. The summary renders to the shared
    # console (stderr), captured here as the other terminal-output tests do.
    from hydra.utils.logger import console

    p = tmp_path / "targets.txt"
    p.write_text("http://a.example/\nhttp://b.example/\n", encoding="utf-8")

    counts = {"http://a.example/": {"high": 2, "low": 1}, "http://b.example/": {"critical": 1}}

    def config_for(t: str) -> ScanConfig:
        return ScanConfig(target=t, scope=ScopeConfig(domains=["example"]), output="rep")

    def fake_run(cfg, **_kw):
        return counts[cfg.target]

    with (
        patch.object(main, "_run_scan", new=fake_run),
        patch.object(main.asyncio, "run", side_effect=lambda c: c),
        console.capture() as cap,
    ):
        main._run_target_file(str(p), config_for, dry_run=False, fail_on=None)
    out = cap.get()
    assert "BATCH SUMMARY" in out
    assert "a.example" in out and "b.example" in out
    # Totals are summed per target (2 + 1 = 3 for the first).
    assert "3" in out


def test_batch_summary_empty_is_noop():
    from hydra.utils.logger import console

    with console.capture() as cap:
        main._print_batch_summary([])
    assert cap.get() == ""
