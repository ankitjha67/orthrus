"""External-tool recon adapters + the `orthrus recon-run` CLI."""

from __future__ import annotations

import json

from orthrus.recon_engine import RECON_REGISTRY
from orthrus.recon_engine.tools import SubfinderAdapter, parse_subdomain_lines


def test_tools_registered():
    assert "subfinder" in RECON_REGISTRY and "amass" in RECON_REGISTRY


def test_parse_subdomain_lines_filters_and_dedups():
    stdout = "api.acme.com\n*.acme.com\nACME.com\napi.acme.com\nevil.com\n\n"
    res = parse_subdomain_lines(stdout, "acme.com", "subfinder")
    assert [a.value for a in res] == ["api.acme.com", "acme.com"]   # dup + evil.com dropped
    assert all(a.kind == "subdomain" and a.source == "subfinder" for a in res)


def test_subfinder_command():
    assert SubfinderAdapter().build_command("acme.com") == [
        "subfinder", "-d", "acme.com", "-silent", "-all"
    ]


def test_recon_run_cli_creates_program_offline(tmp_path, monkeypatch):
    # subfinder binary is absent → the run makes no network calls, proving the CLI
    # path (create program + scope + engine run) end to end.
    import orthrus.main as main

    monkeypatch.setenv("ORTHRUS_DB_URL", f"sqlite+aiosqlite:///{(tmp_path / 'rr.db').as_posix()}")
    from click.testing import CliRunner

    r = CliRunner().invoke(main.cli, [
        "--no-banner", "recon-run", "--program", "lab", "--in-scope", "lab.test",
        "--authorization", "self-owned-lab", "--sources", "subfinder", "--json",
    ])
    assert r.exit_code == 0, r.output
    data = json.loads(r.output[r.output.index("{"):])
    assert data["domains"] == ["lab.test"]
    assert data["discovered"] == 0 and data["new"] == []   # subfinder unavailable → nothing
    assert data["sources_run"] == []

    # re-running without --authorization now works (program exists)
    r2 = CliRunner().invoke(main.cli, [
        "--no-banner", "recon-run", "--program", "lab", "--sources", "subfinder", "--json",
    ])
    assert r2.exit_code == 0, r2.output


def test_recon_run_cli_requires_auth_to_create(tmp_path, monkeypatch):
    import orthrus.main as main

    monkeypatch.setenv("ORTHRUS_DB_URL", f"sqlite+aiosqlite:///{(tmp_path / 'rr2.db').as_posix()}")
    from click.testing import CliRunner

    r = CliRunner().invoke(main.cli, ["--no-banner", "recon-run", "--program", "new-prog"])
    assert r.exit_code != 0
    assert "authorization" in r.output.lower()
