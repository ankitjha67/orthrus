"""`hydra findings`: read-only terminal triage view of a stored scan.

Complements ``scans`` (list scans) and ``report`` (file export): a quick,
network-free look at what a scan found. The JSON path is the machine contract
(stdout only, no raw evidence); the human path renders the shared findings
table. Severity filtering focuses triage on the high-risk end.
"""

from __future__ import annotations

import asyncio
import json

from click.testing import CliRunner

from hydra import main
from hydra.core.schemas import Finding, Severity
from hydra.db.store import Store


def _db_url(tmp_path) -> str:
    return f"sqlite+aiosqlite:///{(tmp_path / 'h.db').as_posix()}"


async def _seed(db_url: str) -> None:
    store = Store(db_url)
    await store.init()
    await store.create_scan("s", "http://t", {}, {})
    await store.add_finding(
        "s",
        Finding(vuln_type="xss", title="Reflected XSS", severity=Severity.MEDIUM, url="http://t/x"),
    )
    await store.add_finding(
        "s",
        Finding(vuln_type="sqli", title="SQL injection", severity=Severity.CRITICAL, url="http://t/q"),
    )
    await store.add_finding(
        "s",
        Finding(vuln_type="cookie", title="Insecure cookie", severity=Severity.LOW, url="http://t/c"),
    )
    await store.close()


def test_findings_json_lists_all_severity_sorted(tmp_path, monkeypatch):
    db_url = _db_url(tmp_path)
    asyncio.run(_seed(db_url))
    monkeypatch.setenv("HYDRA_DB_URL", db_url)

    result = CliRunner().invoke(main.cli, ["--no-banner", "findings", "--scan-id", "s", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert [f["vuln_type"] for f in data] == ["sqli", "xss", "cookie"]  # critical -> low
    # Triage view never leaks raw evidence onto stdout.
    assert all("evidence" not in f and "request_raw" not in f for f in data)


def test_findings_severity_filter_drops_low(tmp_path, monkeypatch):
    db_url = _db_url(tmp_path)
    asyncio.run(_seed(db_url))
    monkeypatch.setenv("HYDRA_DB_URL", db_url)

    result = CliRunner().invoke(
        main.cli, ["--no-banner", "findings", "--scan-id", "s", "--severity", "high", "--json"]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    # Only critical/high survive a 'high' floor; the medium + low are filtered out.
    assert [f["vuln_type"] for f in data] == ["sqli"]


def test_findings_human_table_renders(tmp_path, monkeypatch):
    # The themed table prints to the shared stderr console, which CliRunner can't
    # capture; use console.capture() (as the dry-run plan test does).
    from hydra.utils.logger import console

    db_url = _db_url(tmp_path)
    asyncio.run(_seed(db_url))
    monkeypatch.setenv("HYDRA_DB_URL", db_url)

    with console.capture() as cap:
        asyncio.run(main._list_findings("s", None, False))
    out = cap.get()
    assert "SQL injection" in out
    assert "Reflected XSS" in out
    assert "CRITICAL" in out  # severity rendered, upper-cased


def test_findings_unknown_scan_emits_no_json(tmp_path, monkeypatch):
    # No such scan: the JSON branch must not run, so stdout stays empty (the
    # error goes to stderr) and a consumer can tell "absent" from "[]" (no rows).
    monkeypatch.setenv("HYDRA_DB_URL", _db_url(tmp_path))
    result = CliRunner().invoke(
        main.cli, ["--no-banner", "findings", "--scan-id", "nope", "--json"]
    )
    assert result.exit_code == 0, result.output
    assert "vuln_type" not in result.output


def test_finding_summary_is_triage_only():
    # The summary projection is the stdout contract: triage fields only, never
    # the evidence payload.
    class _Row:
        vuln_type, title, severity, confidence = "xss", "T", "high", "firm"
        url, parameter, cwe, cvss_score, scanner = "http://t/x", "q", "CWE-79", 6.1, "xss_scanner"
        evidence_json = {"request_raw": "secret"}

    summary = main._finding_summary(_Row())
    assert summary["vuln_type"] == "xss"
    assert "evidence" not in summary and "evidence_json" not in summary
