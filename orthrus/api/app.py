"""ORTHRUS REST API — programmatic, read access to scans and findings.

A real FastAPI application backed by the same async store the CLI uses, so scan
results are queryable over HTTP / by other services and dashboards. Read-only by
design in this layer (launching scans is a separate, authenticated concern).

Run with ``orthrus serve`` (needs the ``[api]`` extra: fastapi + uvicorn). The
app is fully exercisable in tests via ``fastapi.testclient.TestClient`` — no
network server required.
"""

from __future__ import annotations

import html
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from orthrus import __version__
from orthrus.core.config import ScopeConfig, get_settings
from orthrus.db.store import Store
from orthrus.proxy.replay import RequestSpec
from orthrus.proxy.replay import replay as _replay
from orthrus.reporting.surface import render_surface_html
from orthrus.utils.scope import ScopeValidator


def _host_of(url: str) -> str:
    return urlsplit(url).netloc.split("@")[-1].split(":")[0]


_REPEATER_BODY = (
    "<p><a href='/'>&larr; all scans</a></p><h1>Repeater</h1>"
    "<p class=muted>Resend a request to an already-scanned (authorized) host and inspect the "
    "response. Scope-enforced — off-target hosts are refused.</p>"
    "<div style='display:grid;grid-template-columns:1fr 1fr;gap:14px'>"
    "<div><label>Method</label><br><select id=m>"
    + "".join(f"<option>{x}</option>" for x in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"))
    + "</select> <input id=u placeholder='https://host/path' style='width:70%'>"
    "<br><label>Headers (one per line, Name: value)</label>"
    "<br><textarea id=h rows=6 style='width:100%'></textarea>"
    "<br><label>Body</label><br><textarea id=b rows=6 style='width:100%'></textarea>"
    "<br><button id=go>Send</button></div>"
    "<div><label>Response</label><pre id=out style='white-space:pre-wrap;word-break:break-all;"
    "background:#0b0d13;border:1px solid #242a36;border-radius:6px;padding:12px;min-height:320px'></pre></div>"
    "</div>"
    "<style>label{color:#9aa6bf;font-size:12px}select,input,textarea{background:#0b0d13;color:#e6e6e6;"
    "border:1px solid #333c4e;border-radius:5px;padding:6px;font-family:inherit}"
    "button{background:#e8491d;color:#fff;border:0;border-radius:6px;padding:8px 18px;margin-top:8px;cursor:pointer}"
    ".muted{color:#9aa6bf;font-size:13px}</style>"
    "<script>"
    "document.getElementById('go').onclick=async()=>{"
    "const out=document.getElementById('out');out.textContent='sending…';"
    "const hdrs={};document.getElementById('h').value.split('\\n').forEach(l=>{"
    "const i=l.indexOf(':');if(i>0)hdrs[l.slice(0,i).trim()]=l.slice(i+1).trim();});"
    "try{const r=await fetch('/api/replay',{method:'POST',headers:{'Content-Type':'application/json'},"
    "body:JSON.stringify({method:document.getElementById('m').value,url:document.getElementById('u').value,"
    "headers:hdrs,body:document.getElementById('b').value})});const d=await r.json();"
    "if(d.error){out.textContent='ERROR: '+d.error;return;}"
    "const hd=(d.headers||[]).map(h=>h[0]+': '+h[1]).join('\\n');"
    "out.textContent=d.status+' '+d.reason+'  ('+d.elapsed_ms+' ms)\\n\\n'+hd+'\\n\\n'+d.body;"
    "}catch(e){out.textContent='ERROR: '+e;}};"
    "</script>"
)

_SEV_COLOR = {
    "critical": "#b30000", "high": "#e8491d", "medium": "#d98800",
    "low": "#3aa775", "info": "#7889a6",
}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _page(title: str, body: str) -> str:
    """Minimal dark-theme HTML shell. Body is assembled from pre-escaped parts."""
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width, initial-scale=1">'
        f"<title>{html.escape(title)}</title><style>"
        "body{font-family:system-ui,'Segoe UI',sans-serif;background:#0f1117;color:#e6e6e6;margin:0;padding:24px}"
        "h1{color:#e8491d;margin:0 0 4px} a{color:#5ab0ff;text-decoration:none} a:hover{text-decoration:underline}"
        "table{border-collapse:collapse;width:100%;margin-top:14px}"
        "th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #242a36;font-size:14px}"
        "th{color:#9aa6bf;font-weight:600} .sev{font-weight:700} code{color:#7fd9c0;word-break:break-all}"
        ".pill{display:inline-block;padding:2px 9px;border-radius:11px;color:#fff;font-size:12px;margin-right:6px}"
        "</style></head><body>" + body + "</body></html>"
    )


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

    # ---------------------------------------------------------- web dashboard
    @app.get("/", response_class=HTMLResponse)
    async def dashboard_index() -> str:
        rows = await app.state.store.list_scans(limit=100)
        trs = "".join(
            "<tr>"
            f"<td><a href='/dashboard/scans/{html.escape(row.id)}'>{html.escape(row.id)}</a></td>"
            f"<td>{html.escape(row.target or '')}</td>"
            f"<td>{html.escape(row.status or '')}</td>"
            f"<td>{count}</td>"
            f"<td>{html.escape(row.started_at.isoformat() if row.started_at else '')}</td>"
            "</tr>"
            for row, count in rows
        )
        body = (
            "<h1>ORTHRUS</h1>"
            f"<p>{len(rows)} scan(s) · <a href='/dashboard/repeater'>Repeater</a> · "
            "<a href='/docs'>API docs</a></p>"
            "<table><tr><th>Scan</th><th>Target</th><th>Status</th><th>Findings</th><th>Started</th></tr>"
            + (trs or "<tr><td colspan=5>No scans yet.</td></tr>")
            + "</table>"
        )
        return _page("ORTHRUS — scans", body)

    @app.get("/dashboard/scans/{scan_id}", response_class=HTMLResponse)
    async def dashboard_scan(scan_id: str) -> str:
        row = await _require_scan(scan_id)
        summary = await app.state.store.severity_counts(scan_id)
        pairs = await app.state.store.get_findings_with_ids(scan_id)
        pairs.sort(key=lambda p: _SEV_RANK.get(p[1].severity.value, 9))
        chips = "".join(
            f"<span class=pill style='background:{_SEV_COLOR.get(k, '#789')}'>{html.escape(k)} {v}</span>"
            for k, v in summary.items()
            if k != "total" and v
        )
        frs = "".join(
            "<tr>"
            f"<td class=sev style='color:{_SEV_COLOR.get(f.severity.value, '#789')}'>{html.escape(f.severity.value)}</td>"
            f"<td>{html.escape(f.confidence.value)}</td>"
            f"<td>{html.escape(f.vuln_type)}</td>"
            f"<td><code>{html.escape(f.url or '')}</code></td>"
            f"<td>{html.escape(f.cwe or '')}</td>"
            "</tr>"
            for _fid, f in pairs
        )
        body = (
            "<p><a href='/'>&larr; all scans</a></p>"
            f"<h1>{html.escape(row.target or scan_id)}</h1>"
            f"<p>{html.escape(scan_id)} · {html.escape(row.status or '')} · "
            f"<a href='/dashboard/scans/{html.escape(scan_id)}/surface'>Attack-surface graph &rarr;</a></p>"
            f"<p>{chips or 'No findings.'}</p>"
            "<table><tr><th>Severity</th><th>Confidence</th><th>Type</th><th>URL</th><th>CWE</th></tr>"
            + (frs or "<tr><td colspan=5>No findings.</td></tr>")
            + "</table>"
        )
        return _page(f"ORTHRUS — {scan_id}", body)

    @app.get("/dashboard/scans/{scan_id}/surface", response_class=HTMLResponse)
    async def dashboard_surface(scan_id: str) -> str:
        row = await _require_scan(scan_id)
        assets = await app.state.store.get_assets(scan_id)
        endpoints = await app.state.store.get_endpoints(scan_id)
        return render_surface_html(row.target or scan_id, assets, endpoints)

    @app.get("/dashboard/repeater", response_class=HTMLResponse)
    async def dashboard_repeater() -> str:
        return _page("ORTHRUS — repeater", _REPEATER_BODY)

    async def _authorized_hosts() -> set[str]:
        rows = await app.state.store.list_scans(limit=500)
        return {_host_of(r.target) for r, _ in rows if r.target and _host_of(r.target)}

    @app.post("/api/replay")
    async def replay_request(payload: dict[str, Any]) -> dict[str, Any]:
        """Resend a request to an already-scanned host (the browser Repeater). Scope-gated
        to hosts that appear as a scan target, so the dashboard can't become an open relay."""
        url = str(payload.get("url") or "")
        host = _host_of(url)
        if not url or not host:
            raise HTTPException(status_code=400, detail="a valid 'url' is required")
        if host not in await _authorized_hosts():
            raise HTTPException(status_code=403, detail=f"host '{host}' is not a scanned/authorized target")
        spec = RequestSpec(
            method=str(payload.get("method") or "GET").upper(),
            url=url,
            headers={str(k): str(v) for k, v in (payload.get("headers") or {}).items()},
            body=str(payload.get("body") or ""),
        )
        validator = ScopeValidator(ScopeConfig(domains=[host]))
        result = await _replay(spec, validator, follow_redirects=bool(payload.get("follow_redirects")))
        return {
            "method": result.method, "url": result.url, "status": result.status,
            "reason": result.reason, "elapsed_ms": result.elapsed_ms,
            "headers": result.headers, "body": result.body, "error": result.error,
        }

    return app


__all__ = ["create_app"]
