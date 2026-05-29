"""`orthrus diff`: compare two scans of the same target (retest view).

Findings are matched across scans by type + URL + parameter, then partitioned
into NEW (regressions), FIXED, and STILL-PRESENT. The JSON path is the machine
contract; --fail-on-new is the CI regression gate (exit 3). Read-only, no
network.
"""

from __future__ import annotations

import asyncio
import json

from click.testing import CliRunner

from orthrus import main
from orthrus.core.schemas import Finding, Severity
from orthrus.db.store import Store


def _db_url(tmp_path) -> str:
    return f"sqlite+aiosqlite:///{(tmp_path / 'h.db').as_posix()}"


def _f(vuln_type: str, url: str, sev: Severity = Severity.HIGH) -> Finding:
    return Finding(vuln_type=vuln_type, title=f"{vuln_type} at {url}", severity=sev, url=url)


async def _seed(db_url: str) -> None:
    store = Store(db_url)
    await store.init()
    # base: sqli (later fixed) + xss (persists)
    await store.create_scan("base", "http://t", {}, {})
    await store.add_finding("base", _f("sqli", "http://t/q", Severity.CRITICAL))
    await store.add_finding("base", _f("xss", "http://t/s", Severity.MEDIUM))
    # against: xss (persists) + csrf (new)
    await store.create_scan("against", "http://t", {}, {})
    await store.add_finding("against", _f("xss", "http://t/s", Severity.MEDIUM))
    await store.add_finding("against", _f("csrf", "http://t/c", Severity.HIGH))
    await store.close()


def test_diff_json_partitions_new_fixed_persisting(tmp_path, monkeypatch):
    db_url = _db_url(tmp_path)
    asyncio.run(_seed(db_url))
    monkeypatch.setenv("ORTHRUS_DB_URL", db_url)

    result = CliRunner().invoke(
        main.cli, ["--no-banner", "diff", "--base", "base", "--against", "against", "--json"]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert [f["vuln_type"] for f in data["new"]] == ["csrf"]
    assert [f["vuln_type"] for f in data["fixed"]] == ["sqli"]
    assert [f["vuln_type"] for f in data["persisting"]] == ["xss"]


def test_diff_fail_on_new_exits_nonzero(tmp_path, monkeypatch):
    db_url = _db_url(tmp_path)
    asyncio.run(_seed(db_url))
    monkeypatch.setenv("ORTHRUS_DB_URL", db_url)

    result = CliRunner().invoke(
        main.cli,
        ["--no-banner", "diff", "--base", "base", "--against", "against", "--fail-on-new"],
    )
    assert result.exit_code == main.FAIL_ON_EXIT_CODE


def test_diff_against_self_has_no_new(tmp_path, monkeypatch):
    # Diffing a scan against itself: nothing new, nothing fixed -> gate passes.
    db_url = _db_url(tmp_path)
    asyncio.run(_seed(db_url))
    monkeypatch.setenv("ORTHRUS_DB_URL", db_url)

    result = CliRunner().invoke(
        main.cli,
        ["--no-banner", "diff", "--base", "base", "--against", "base", "--fail-on-new", "--json"],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["new"] == [] and data["fixed"] == []
    assert {f["vuln_type"] for f in data["persisting"]} == {"sqli", "xss"}


def test_diff_severity_filter_excludes_below_floor(tmp_path, monkeypatch):
    # With a 'high' floor, the MEDIUM xss drops out of both sides, so it is no
    # longer reported as persisting.
    db_url = _db_url(tmp_path)
    asyncio.run(_seed(db_url))
    monkeypatch.setenv("ORTHRUS_DB_URL", db_url)

    result = CliRunner().invoke(
        main.cli,
        ["--no-banner", "diff", "--base", "base", "--against", "against",
         "--severity", "high", "--json"],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert [f["vuln_type"] for f in data["persisting"]] == []  # xss was MEDIUM
    assert [f["vuln_type"] for f in data["new"]] == ["csrf"]
    assert [f["vuln_type"] for f in data["fixed"]] == ["sqli"]


def test_diff_unknown_scan_errors(tmp_path, monkeypatch):
    db_url = _db_url(tmp_path)
    asyncio.run(_seed(db_url))
    monkeypatch.setenv("ORTHRUS_DB_URL", db_url)

    result = CliRunner().invoke(
        main.cli, ["--no-banner", "diff", "--base", "base", "--against", "ghost", "--json"]
    )
    assert result.exit_code != 0
    assert "no such scan: ghost" in result.output


def test_partition_diff_is_pure():
    # Unit-level: partitioning is keyed on (vuln_type, url, parameter).
    class _Row:
        def __init__(self, vuln_type, url, severity="high", parameter=None):
            self.vuln_type, self.url, self.severity, self.parameter = vuln_type, url, severity, parameter

    base = [_Row("sqli", "http://t/q"), _Row("xss", "http://t/s")]
    against = [_Row("xss", "http://t/s"), _Row("idor", "http://t/u", parameter="id")]
    parts = main._partition_diff(base, against)
    assert [r.vuln_type for r in parts["new"]] == ["idor"]
    assert [r.vuln_type for r in parts["fixed"]] == ["sqli"]
    assert [r.vuln_type for r in parts["persisting"]] == ["xss"]


def test_diff_human_render(tmp_path, monkeypatch):
    from orthrus.utils.logger import console

    db_url = _db_url(tmp_path)
    asyncio.run(_seed(db_url))
    monkeypatch.setenv("ORTHRUS_DB_URL", db_url)

    base_rows, against_rows = asyncio.run(main._load_diff_rows("base", "against", None))
    parts = main._partition_diff(base_rows, against_rows)
    with console.capture() as cap:
        main._print_diff("base", "against", parts)
    out = cap.get()
    assert "SCAN DIFF" in out
    assert "csrf" in out  # the new finding is rendered
    assert "sqli" in out  # the fixed finding is rendered
