"""`orthrus modules`: discoverability listing of scanner / exploit modules.

The JSON path is the deterministic contract (stdout), so assertions key off it;
the human table path is exercised for a clean exit.
"""

from __future__ import annotations

import json

from click.testing import CliRunner

from orthrus import main


def test_modules_json_lists_known_scanners():
    runner = CliRunner()
    result = runner.invoke(main.cli, ["--no-banner", "modules", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)

    names = {s["name"] for s in data["scanners"]}
    # A representative spread of the built-in scanner suite must be present.
    assert {"sqli", "reflected-xss", "ssrf", "security-headers"} <= names
    # Each entry carries the metadata an operator needs to choose modules.
    for s in data["scanners"]:
        assert s["vuln_type"]
        assert s["min_aggressiveness"] in {"passive", "normal", "aggressive"}
    assert len(data["scanners"]) >= 20


def test_modules_json_lists_exploit_confirmers():
    runner = CliRunner()
    result = runner.invoke(main.cli, ["--no-banner", "modules", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)

    exploit_names = {e["name"] for e in data["exploits"]}
    assert exploit_names  # at least one confirmation module is registered
    # Every confirmer declares which vuln types it handles.
    for e in data["exploits"]:
        assert isinstance(e["handles"], list)


def test_modules_descriptions_present_and_prd_free():
    runner = CliRunner()
    result = runner.invoke(main.cli, ["--no-banner", "modules", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)

    # Descriptions fall back to the module docstring, so they should be non-empty
    # for the core scanners - and must never leak the internal PRD references.
    described = {s["name"]: s["description"] for s in data["scanners"]}
    assert described["sqli"]
    for desc in described.values():
        assert "PRD" not in desc


def test_modules_human_table_exits_clean():
    runner = CliRunner()
    result = runner.invoke(main.cli, ["--no-banner", "modules"])
    assert result.exit_code == 0, result.output


def test_modules_detail_by_name_filters_to_one():
    runner = CliRunner()
    result = runner.invoke(main.cli, ["--no-banner", "modules", "sqli", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)

    names = {s["name"] for s in data["scanners"]}
    assert "sqli" in names
    # Unrelated scanners are filtered out of a single-module view.
    assert "security-headers" not in names


def test_modules_detail_by_vuln_type_groups_family():
    # "xss" is a vuln_type shared by several scanners (reflected/dom/stored).
    runner = CliRunner()
    result = runner.invoke(main.cli, ["--no-banner", "modules", "xss", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)

    assert data["scanners"]  # at least one xss-family scanner matched
    assert all(s["vuln_type"] == "xss" for s in data["scanners"])


def test_modules_unknown_name_errors():
    runner = CliRunner()
    result = runner.invoke(main.cli, ["--no-banner", "modules", "no-such-module"])
    assert result.exit_code != 0
    assert "no-such-module" in result.output


def test_modules_human_detail_exits_clean():
    runner = CliRunner()
    result = runner.invoke(main.cli, ["--no-banner", "modules", "sqli"])
    assert result.exit_code == 0, result.output
