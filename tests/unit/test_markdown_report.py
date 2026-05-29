"""Markdown report output: structure, table sanitisation, and the empty case."""

from __future__ import annotations

from hydra.core.schemas import Confidence, Finding, ParamLocation, Severity
from hydra.db.store import Store
from hydra.reporting.generator import _build_context, _md_cell, _write_markdown


def test_md_cell_escapes_pipes_and_newlines():
    assert _md_cell("a|b") == "a\\|b"
    assert _md_cell("line1\nline2") == "line1 line2"
    assert _md_cell(None) == ""


def _read_text(path: str) -> str:
    # Sync reader keeps the blocking open() out of the async test (ruff ASYNC230).
    with open(path, encoding="utf-8") as fh:
        return fh.read()


async def test_markdown_report_structure(tmp_path):
    store = Store(f"sqlite+aiosqlite:///{(tmp_path / 'h.db').as_posix()}")
    await store.init()
    try:
        scan_id = "scan-md"
        await store.create_scan(scan_id, "http://target", {}, {})
        await store.add_finding(
            scan_id,
            Finding(
                vuln_type="sqli",
                title="SQL injection in id",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                url="http://target/search?id=1",
                parameter="id",
                param_location=ParamLocation.QUERY,
                cwe="CWE-89",
                cvss_score=9.8,
                description="Boolean-based blind SQL injection.",
                remediation="Use parameterized queries.",
            ),
        )
        context = await _build_context(store, scan_id, None, None)
    finally:
        await store.close()

    md = _write_markdown(context)
    assert md.startswith("# HYDRA Security Report")
    assert "authorized security testing only" in md.lower()
    assert "## Summary" in md
    assert "## Findings" in md
    assert "## Details" in md
    assert "SQL injection in id" in md
    assert "http://target/search?id=1" in md
    assert "Use parameterized queries." in md
    assert "`HIGH`" in md  # severity badge
    # Table header present
    assert "| # | Severity | CVSS | Type | Title | URL | Confidence |" in md


async def test_markdown_report_empty_findings(tmp_path):
    store = Store(f"sqlite+aiosqlite:///{(tmp_path / 'h.db').as_posix()}")
    await store.init()
    try:
        await store.create_scan("empty", "http://t", {}, {})
        context = await _build_context(store, "empty", None, None)
    finally:
        await store.close()

    md = _write_markdown(context)
    assert "_No findings._" in md


async def test_generate_report_writes_markdown_file(tmp_path):
    from hydra.reporting.generator import generate_report

    store = Store(f"sqlite+aiosqlite:///{(tmp_path / 'h.db').as_posix()}")
    await store.init()
    try:
        await store.create_scan("s", "http://t", {}, {})
        await store.add_finding(
            "s",
            Finding(vuln_type="xss", title="XSS", severity=Severity.MEDIUM, url="http://t/x"),
        )
        out = str(tmp_path / "report")
        path = await generate_report(store, "s", "md", out)
    finally:
        await store.close()

    assert path.endswith(".md")
    text = _read_text(path)
    assert "# HYDRA Security Report" in text
    assert "XSS" in text
