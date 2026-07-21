"""ORTHRUS MCP server - expose scans/findings as tools an AI agent can call.

The tool *logic* lives in plain async functions (``*_data``) that query the same
store the CLI/API use and return JSON-able data, so they're unit-testable with no
MCP SDK. ``build_server()`` wraps them as MCP tools via the official SDK's
high-level ``FastMCP`` (imported lazily, so this module loads without the
``[mcp]`` extra). Run with ``orthrus mcp`` (stdio transport).
"""

from __future__ import annotations

from typing import Any

from orthrus.core.config import get_settings
from orthrus.db.store import Store


def _scan_dict(row: Any, findings: int | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": row.id,
        "target": row.target,
        "status": row.status,
        "phase": row.phase,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
    }
    if findings is not None:
        data["findings"] = findings
    return data


async def list_scans_data(db_url: str, limit: int = 50) -> list[dict[str, Any]]:
    store = Store(db_url)
    try:
        await store.init()
        rows = await store.list_scans(limit=limit)
        return [_scan_dict(row, count) for row, count in rows]
    finally:
        await store.close()


async def scan_detail_data(db_url: str, scan_id: str) -> dict[str, Any]:
    store = Store(db_url)
    try:
        await store.init()
        row = await store.get_scan(scan_id)
        if row is None:
            return {"error": f"scan '{scan_id}' not found"}
        data = _scan_dict(row)
        data["summary"] = await store.severity_counts(scan_id)
        return data
    finally:
        await store.close()


async def findings_data(db_url: str, scan_id: str) -> list[dict[str, Any]]:
    store = Store(db_url)
    try:
        await store.init()
        if await store.get_scan(scan_id) is None:
            return []
        pairs = await store.get_findings_with_ids(scan_id)
        return [{**finding.model_dump(mode="json"), "id": fid} for fid, finding in pairs]
    finally:
        await store.close()


def build_server(db_url: str | None = None) -> Any:
    """Construct the ORTHRUS FastMCP server with read tools. Needs the [mcp] extra."""
    from mcp.server.fastmcp import FastMCP

    url = db_url or get_settings().db_url
    server = FastMCP("orthrus")

    @server.tool()
    async def list_scans(limit: int = 50) -> list[dict[str, Any]]:
        """List recent ORTHRUS scans (newest first) with their finding counts."""
        return await list_scans_data(url, limit)

    @server.tool()
    async def get_scan(scan_id: str) -> dict[str, Any]:
        """Get a scan's status, phase, and severity summary by scan id."""
        return await scan_detail_data(url, scan_id)

    @server.tool()
    async def get_findings(scan_id: str) -> list[dict[str, Any]]:
        """Get all findings for a scan id (vuln type, severity, URL, CWE, evidence)."""
        return await findings_data(url, scan_id)

    @server.tool()
    async def list_modules() -> dict[str, Any]:
        """List the available ORTHRUS scanner module names."""
        from orthrus.scanners.registry import available_modules

        return {"scanners": available_modules()}

    return server


__all__ = ["build_server", "list_scans_data", "scan_detail_data", "findings_data"]
