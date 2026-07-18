"""Re-render a saved program's campaign from stored scans (report_from_scans)."""

from __future__ import annotations

import asyncio

from orthrus.bounty.campaign import report_from_scans, write_reports
from orthrus.bounty.scope_intake import parse_program_scope
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.db.store import Store


def _db_url(tmp_path) -> str:
    return f"sqlite+aiosqlite:///{(tmp_path / 'h.db').as_posix()}"


def _seed(db_url: str) -> None:
    async def run():
        store = Store(db_url)
        await store.init()
        await store.create_scan("s1", "https://api.acme.com", {}, {})
        await store.add_finding("s1", Finding(
            vuln_type="sqli", title="SQL injection", severity=Severity.CRITICAL,
            confidence=Confidence.FIRM, url="https://api.acme.com/item?id=1", cwe="CWE-89",
            evidence=Evidence(request_raw="GET /item?id=1 HTTP/1.1")))
        await store.add_finding("s1", Finding(
            vuln_type="security-headers", title="Missing HSTS", severity=Severity.LOW,
            confidence=Confidence.FIRM, url="https://api.acme.com/"))
        # out-of-scope finding: must be dropped on re-render
        await store.add_finding("s1", Finding(
            vuln_type="xss", title="XSS", severity=Severity.HIGH,
            confidence=Confidence.FIRM, url="https://evil.example/x"))
        await store.close()

    asyncio.run(run())


def test_report_from_scans_aggregates_and_scopes(tmp_path, monkeypatch):
    monkeypatch.setenv("ORTHRUS_DB_URL", _db_url(tmp_path))
    _seed(_db_url(tmp_path))
    scope = parse_program_scope("*.acme.com\n")

    report = asyncio.run(report_from_scans(["s1"], scope, min_confidence="firm"))
    types = {g.lead.vuln_type for g in report.groups}
    assert types == {"sqli", "security-headers"}   # evil.example dropped as out-of-scope
    assert report.out_of_scope == 1

    # a mute rule for the header noise leaves only the SQLi
    muted = asyncio.run(report_from_scans(
        ["s1"], scope, min_confidence="firm",
        suppressions=[{"vuln_type": "security-headers"}]))
    assert {g.lead.vuln_type for g in muted.groups} == {"sqli"}
    assert muted.suppressed == 1


def test_rerender_writes_platform_reports(tmp_path, monkeypatch):
    monkeypatch.setenv("ORTHRUS_DB_URL", _db_url(tmp_path))
    _seed(_db_url(tmp_path))
    scope = parse_program_scope("*.acme.com\n")
    report = asyncio.run(report_from_scans(["s1"], scope, min_confidence="firm"))

    out = tmp_path / "hackerone-out"
    files = write_reports(report, out, program_name="acme", platform="hackerone")
    assert "README.md" in files and "findings.json" in files
    # the SQLi (critical) ranks first; its file exists and is HackerOne-shaped
    bug = next(f for f in files if f.startswith("bug-01"))
    body = (out / bug).read_text(encoding="utf-8")
    assert "## Steps To Reproduce" in body   # HackerOne heading casing
