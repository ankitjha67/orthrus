"""ORTHRUS REST API — programmatic, read access to scans and findings.

A real FastAPI application backed by the same async store the CLI uses, so scan
results are queryable over HTTP / by other services and dashboards. Read-only by
design in this layer (launching scans is a separate, authenticated concern).

Run with ``orthrus serve`` (needs the ``[api]`` extra: fastapi + uvicorn). The
app is fully exercisable in tests via ``fastapi.testclient.TestClient`` — no
network server required.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException

from orthrus import __version__
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


def create_app(db_url: str | None = None) -> FastAPI:
    """Build the ORTHRUS API app. ``db_url`` overrides the configured store (tests)."""
    settings = get_settings()
    url = db_url or settings.db_url

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        store = Store(url, encryption_key=settings.encryption_key)
        await store.init()
        app.state.store = store
        try:
            yield
        finally:
            await store.close()

    app = FastAPI(
        title="ORTHRUS API",
        version=__version__,
        description="Read access to ORTHRUS scans and findings.",
        lifespan=lifespan,
    )

    async def _require_scan(scan_id: str) -> Any:
        row = await app.state.store.get_scan(scan_id)
        if row is None:
            raise HTTPException(status_code=404, detail=f"scan '{scan_id}' not found")
        return row

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/scans")
    async def list_scans(limit: int = 50, status: str | None = None) -> list[dict[str, Any]]:
        rows = await app.state.store.list_scans(limit=limit, status=status)
        return [_scan_dict(row, count) for row, count in rows]

    @app.get("/api/scans/{scan_id}")
    async def get_scan(scan_id: str) -> dict[str, Any]:
        row = await _require_scan(scan_id)
        data = _scan_dict(row)
        data["summary"] = await app.state.store.severity_counts(scan_id)
        return data

    @app.get("/api/scans/{scan_id}/findings")
    async def get_findings(scan_id: str) -> list[dict[str, Any]]:
        await _require_scan(scan_id)
        pairs = await app.state.store.get_findings_with_ids(scan_id)
        return [{**finding.model_dump(mode="json"), "id": fid} for fid, finding in pairs]

    @app.get("/api/scans/{scan_id}/report")
    async def report(scan_id: str) -> dict[str, Any]:
        row = await _require_scan(scan_id)
        pairs = await app.state.store.get_findings_with_ids(scan_id)
        return {
            "scan": _scan_dict(row),
            "summary": await app.state.store.severity_counts(scan_id),
            "findings": [{**f.model_dump(mode="json"), "id": fid} for fid, f in pairs],
        }

    return app


__all__ = ["create_app"]
