"""Report output to stdout (``-o -``): pipeline-friendly text reports.

Text formats stream to stdout instead of a file when the output path is "-"
(so ``orthrus report --format json -o - | jq`` works); PDF, being binary, is
rejected. generate_report returns "-" to signal the report went to stdout.
"""

from __future__ import annotations

import json

import pytest

from orthrus.core.schemas import Finding, Severity
from orthrus.db.store import Store
from orthrus.reporting.generator import generate_report


async def _store_with_finding(tmp_path) -> Store:
    store = Store(f"sqlite+aiosqlite:///{(tmp_path / 'h.db').as_posix()}")
    await store.init()
    await store.create_scan("s", "http://t", {}, {})
    await store.add_finding(
        "s",
        Finding(vuln_type="xss", title="XSS finding", severity=Severity.MEDIUM, url="http://t/x"),
    )
    return store


async def test_json_report_streams_to_stdout(tmp_path, capsys):
    store = await _store_with_finding(tmp_path)
    try:
        path = await generate_report(store, "s", "json", "-")
    finally:
        await store.close()

    assert path == "-"  # signals stdout, not a file
    out = capsys.readouterr().out
    data = json.loads(out)  # stdout is valid, parseable JSON
    assert any(f["title"] == "XSS finding" for f in data["findings"])


async def test_markdown_report_streams_to_stdout(tmp_path, capsys):
    store = await _store_with_finding(tmp_path)
    try:
        path = await generate_report(store, "s", "md", "-")
    finally:
        await store.close()

    assert path == "-"
    out = capsys.readouterr().out
    assert out.startswith("# ORTHRUS Security Report")
    assert "XSS finding" in out


async def test_pdf_to_stdout_is_rejected(tmp_path):
    store = await _store_with_finding(tmp_path)
    try:
        with pytest.raises(ValueError, match="cannot stream a PDF"):
            await generate_report(store, "s", "pdf", "-")
    finally:
        await store.close()


async def test_file_output_still_writes_with_extension(tmp_path):
    # Regression: the "-" path must not disturb normal file output.
    store = await _store_with_finding(tmp_path)
    try:
        path = await generate_report(store, "s", "json", str(tmp_path / "r"))
    finally:
        await store.close()
    assert path.endswith(".json")
