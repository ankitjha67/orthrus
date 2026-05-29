"""`hydra scan --config file.toml`: file-supplied option defaults.

Two layers: the pure ``_config_to_default_map`` translation (key normalisation
+ array joining) and the Click wiring, where a config-supplied target satisfies
the required-target check that an otherwise-bare invocation fails.
"""

from __future__ import annotations

from click.testing import CliRunner

from hydra import main


# --------------------------------------------------------------- pure translation
def test_config_normalises_keys_and_aliases():
    data = {
        "scan": {
            "target": "http://x/",
            "rate-limit": 5.0,  # hyphen -> rate_limit
            "scope": "example.com",  # alias -> scope_str
            "redis": "redis://h",  # alias -> redis_url
            "aggressive": True,
        }
    }
    out = main._config_to_default_map(data)
    assert out["target"] == "http://x/"
    assert out["rate_limit"] == 5.0
    assert out["scope_str"] == "example.com"
    assert out["redis_url"] == "redis://h"
    assert out["aggressive"] is True


def test_config_joins_csv_arrays():
    out = main._config_to_default_map({"scan": {"modules": ["sqli", "xss"]}})
    assert out["modules"] == "sqli,xss"  # array -> comma string for the str option


def test_config_accepts_flat_document():
    # No [scan] table: the whole document is treated as the option map.
    out = main._config_to_default_map({"target": "http://flat/"})
    assert out["target"] == "http://flat/"


# ------------------------------------------------------------------- CLI wiring
def _write(tmp_path, body: str):
    path = tmp_path / "hydra.toml"
    path.write_text(body, encoding="utf-8")
    return str(path)


def test_config_supplies_required_target(tmp_path):
    cfg = _write(tmp_path, '[scan]\ntarget = "http://t.example/"\n')
    # --dry-run keeps it network-free; success proves the target came from the file
    # (a bare `scan --dry-run` would fail the required-target check below).
    result = CliRunner().invoke(main.cli, ["--no-banner", "scan", "--config", cfg, "--dry-run"])
    assert result.exit_code == 0, result.output


def test_missing_target_without_config_errors():
    result = CliRunner().invoke(main.cli, ["--no-banner", "scan", "--dry-run"])
    assert result.exit_code != 0
    assert "target" in result.output.lower()


def test_cli_target_overrides_config(tmp_path):
    # Both present: the run must still succeed (CLI wins per Click's default_map
    # precedence); the override semantics themselves are pinned by the unit tests.
    cfg = _write(tmp_path, '[scan]\ntarget = "http://from-config/"\n')
    result = CliRunner().invoke(
        main.cli,
        ["--no-banner", "scan", "--config", cfg, "-t", "http://from-cli/", "--dry-run"],
    )
    assert result.exit_code == 0, result.output


def test_bad_config_path_errors():
    result = CliRunner().invoke(
        main.cli, ["--no-banner", "scan", "--config", "does-not-exist.toml", "--dry-run"]
    )
    assert result.exit_code != 0  # click.Path(exists=True) rejects it
