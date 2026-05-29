"""ORTHRUS MCP server — tool-logic functions (SDK-free) + server construction."""

from __future__ import annotations

import asyncio

import pytest

from orthrus.core import schemas
from orthrus.db.store import Store
from orthrus.mcp_server import findings_data, list_scans_data, scan_detail_data


@pytest.fixture
def db_url(tmp_path) -> str:
    url = f"sqlite+aiosqlite:///{tmp_path / 'mcp.sqlite3'}"

    async def seed() -> None:
        store = Store(url)
        await store.init()
        await store.create_scan("scan-mcp", "https://t.example", {}, {})
        await store.add_finding(
            "scan-mcp",
            schemas.Finding(
                vuln_type="sqli",
                title="SQLi",
                severity=schemas.Severity.HIGH,
                confidence=schemas.Confidence.FIRM,
                url="https://t.example/a",
                description="d",
                remediation="r",
                scanner="sqli",
                evidence=schemas.Evidence(),
            ),
        )
        await store.set_scan_status("scan-mcp", "completed", completed=True)
        await store.close()

    asyncio.run(seed())
    return url


async def test_list_scans_data(db_url) -> None:
    rows = await list_scans_data(db_url)
    assert any(r["id"] == "scan-mcp" and r["findings"] == 1 for r in rows)


async def test_scan_detail_data(db_url) -> None:
    detail = await scan_detail_data(db_url, "scan-mcp")
    assert detail["target"] == "https://t.example"
    assert detail["summary"]["high"] == 1
    assert "error" in await scan_detail_data(db_url, "no-such-scan")


async def test_findings_data(db_url) -> None:
    findings = await findings_data(db_url, "scan-mcp")
    assert len(findings) == 1
    assert findings[0]["vuln_type"] == "sqli"
    assert await findings_data(db_url, "no-such-scan") == []


def test_build_server_constructs() -> None:
    pytest.importorskip("mcp")
    from orthrus.mcp_server import build_server

    server = build_server(db_url="sqlite+aiosqlite:///:memory:")
    assert server is not None
    assert hasattr(server, "run")  # FastMCP server is runnable
