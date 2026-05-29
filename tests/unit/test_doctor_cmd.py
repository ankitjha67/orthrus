"""`orthrus doctor`: read-only, network-free environment probe.

The JSON path is the deterministic contract; the human table is exercised for a
clean exit. Detection is by import/binary lookup only, so the command must
never fail regardless of which optional extras are installed.
"""

from __future__ import annotations

import json

from click.testing import CliRunner

from orthrus import main


def test_doctor_json_reports_capabilities():
    result = CliRunner().invoke(main.cli, ["--no-banner", "doctor", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)

    assert data["orthrus_version"]
    assert data["python"]
    caps = data["capabilities"]
    assert len(caps) >= 5
    names = {c["name"] for c in caps}
    # A representative spread of the optional integrations must be reported.
    assert any("Playwright" in n for n in names)
    assert any("nmap" in n for n in names)


def test_doctor_capability_shape():
    result = CliRunner().invoke(main.cli, ["--no-banner", "doctor", "--json"])
    data = json.loads(result.output)
    for cap in data["capabilities"]:
        assert isinstance(cap["available"], bool)
        assert cap["name"] and cap["purpose"] and cap["enable"]


def test_doctor_human_exits_clean():
    result = CliRunner().invoke(main.cli, ["--no-banner", "doctor"])
    assert result.exit_code == 0, result.output


def test_collect_diagnostics_is_network_free_and_pure():
    # Calling the collector twice yields the same capability verdicts (no side
    # effects, no flakiness from network state).
    first = main._collect_diagnostics()
    second = main._collect_diagnostics()
    assert [c["available"] for c in first["capabilities"]] == [
        c["available"] for c in second["capabilities"]
    ]
