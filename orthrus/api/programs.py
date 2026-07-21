"""Operator-graph REST API — Programs, scope, assets, findings, cost (PRD §7.1, Phase 0).

CRUD over the v2.0 unified domain (``orthrus.model.store.ProgramGraph``) so the
cockpit and other services drive the same graph the CLI does. Mutations are
gated by a local bearer token when ``ORTHRUS_API_TOKEN`` is set (off in local
dev); deny-by-default authorization is enforced by the DAL and surfaced as HTTP
400. Read routes are open.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api", tags=["operator-graph"])


# --------------------------------------------------------------- request models
class ProgramCreate(BaseModel):
    name: str
    authorization_source: str
    platform: str = "direct"
    policy_url: str | None = None
    jurisdiction: str | None = None
    priority: int = 3
    reward_range: dict = Field(default_factory=dict)
    rate_limit_hint: dict = Field(default_factory=dict)
    contact_email: str | None = None
    tags: list = Field(default_factory=list)


class ProgramUpdate(BaseModel):
    name: str | None = None
    platform: str | None = None
    authorization_source: str | None = None
    policy_url: str | None = None
    jurisdiction: str | None = None
    priority: int | None = None
    is_paused: bool | None = None
    is_read_only: bool | None = None
    reward_range: dict | None = None
    rate_limit_hint: dict | None = None
    contact_email: str | None = None
    notes_md: str | None = None
    tags: list | None = None


class ScopeEntryCreate(BaseModel):
    value: str
    entry_type: str = "in"
    kind: str = "domain"
    ports: list | None = None
    protocols: list | None = None


class AssetRecord(BaseModel):
    kind: str
    canonical_value: str
    display_value: str | None = None
    discovered_by: str | None = None
    fingerprint: dict = Field(default_factory=dict)
    metadata: dict = Field(default_factory=dict)


class FindingUpdate(BaseModel):
    status: str | None = None
    assigned_to: str | None = None
    hunter_notes_md: str | None = None
    llm_fp_confidence: float | None = None


class NoteCreate(BaseModel):
    title: str
    markdown: str = ""
    tags: list = Field(default_factory=list)
    finding_id: str | None = None
    asset_id: str | None = None


class CopilotQuery(BaseModel):
    query: str
    k: int = 5


# --------------------------------------------------------------- serialization
def _dt(value) -> str | None:
    return value.isoformat() if value else None


def program_dict(p) -> dict[str, Any]:
    return {
        "id": p.id, "name": p.name, "platform": p.platform,
        "authorization_source": p.authorization_source, "policy_url": p.policy_url,
        "jurisdiction": p.jurisdiction, "priority": p.priority,
        "is_paused": p.is_paused, "is_read_only": p.is_read_only,
        "reward_range": p.reward_range, "rate_limit_hint": p.rate_limit_hint,
        "contact_email": p.contact_email, "tags": p.tags,
        "created_at": _dt(p.created_at), "updated_at": _dt(p.updated_at),
    }


def scope_dict(s) -> dict[str, Any]:
    return {
        "id": s.id, "entry_type": s.entry_type, "kind": s.kind, "value": s.value,
        "ports": s.ports, "protocols": s.protocols, "is_active": s.is_active,
        "added_at": _dt(s.added_at),
    }


def asset_dict(a) -> dict[str, Any]:
    return {
        "id": a.id, "kind": a.kind, "canonical_value": a.canonical_value,
        "display_value": a.display_value, "is_alive": a.is_alive,
        "is_wildcard_noise": a.is_wildcard_noise, "trust_score": a.trust_score,
        "fingerprint": a.fingerprint, "metadata": a.metadata_json,
        "discovered_by": a.discovered_by,
        "first_seen_at": _dt(a.first_seen_at), "last_seen_at": _dt(a.last_seen_at),
    }


def note_dict(n) -> dict[str, Any]:
    return {
        "id": n.id, "title": n.title, "markdown": n.markdown, "tags": n.tags,
        "program_id": n.program_id, "asset_id": n.asset_id, "finding_id": n.finding_id,
        "created_at": _dt(n.created_at), "updated_at": _dt(n.updated_at),
    }


def endpoint_dict(e) -> dict[str, Any]:
    return {
        "id": e.id, "asset_id": e.asset_id, "method": e.method, "path": e.path,
        "query_params": e.query_params, "body_params": e.body_params,
        "response_status": e.response_status, "response_content_type": e.response_content_type,
        "response_size": e.response_size, "juicy_score": e.juicy_score,
        "probe_count": e.probe_count, "last_probed_at": _dt(e.last_probed_at),
    }


def finding_dict(f) -> dict[str, Any]:
    return {
        "id": f.id, "vuln_class": f.vuln_class, "title": f.title,
        "severity": f.severity, "confidence": f.confidence, "status": f.status,
        "signature": f.signature, "priority_score": f.priority_score,
        "cwe_id": f.cwe_id, "cvss_v3_score": f.cvss_v3_score,
        "found_by_tool": f.found_by_tool, "discovered_at": _dt(f.discovered_at),
    }


# ------------------------------------------------------------------ auth gate
def require_write(request: Request) -> None:
    """Gate mutations behind a bearer token when ORTHRUS_API_TOKEN is configured."""
    token = os.environ.get("ORTHRUS_API_TOKEN")
    if not token:
        return  # local single-user dev: open
    if request.headers.get("authorization", "") != f"Bearer {token}":
        raise HTTPException(status_code=401, detail="missing or invalid API token")


def _graph(request: Request):
    return request.app.state.graph


async def _require_program(request: Request, program_id: str):
    program = await _graph(request).get_program(program_id)
    if program is None:
        raise HTTPException(status_code=404, detail=f"program '{program_id}' not found")
    return program


# ------------------------------------------------------------------- programs
@router.get("/programs")
async def list_programs(request: Request) -> list[dict[str, Any]]:
    return [program_dict(p) for p in await _graph(request).list_programs()]


@router.post("/programs", status_code=201, dependencies=[Depends(require_write)])
async def create_program(request: Request, body: ProgramCreate) -> dict[str, Any]:
    try:
        p = await _graph(request).create_program(
            body.name, body.authorization_source, platform=body.platform,
            policy_url=body.policy_url, jurisdiction=body.jurisdiction,
            priority=body.priority, reward_range=body.reward_range,
            rate_limit_hint=body.rate_limit_hint, contact_email=body.contact_email,
            tags=body.tags,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return program_dict(p)


@router.get("/programs/{program_id}")
async def get_program(request: Request, program_id: str) -> dict[str, Any]:
    return program_dict(await _require_program(request, program_id))


@router.patch("/programs/{program_id}", dependencies=[Depends(require_write)])
async def update_program(request: Request, program_id: str, body: ProgramUpdate) -> dict[str, Any]:
    await _require_program(request, program_id)
    fields = {k: v for k, v in body.model_dump().items() if v is not None}
    try:
        p = await _graph(request).update_program(program_id, **fields)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return program_dict(p)


@router.delete("/programs/{program_id}", dependencies=[Depends(require_write)])
async def delete_program(request: Request, program_id: str) -> dict[str, Any]:
    if not await _graph(request).delete_program(program_id):
        raise HTTPException(status_code=404, detail=f"program '{program_id}' not found")
    return {"deleted": program_id}


# ---------------------------------------------------------------------- scope
@router.get("/programs/{program_id}/scope")
async def list_scope(request: Request, program_id: str,
                     active_only: bool = True) -> list[dict[str, Any]]:
    await _require_program(request, program_id)
    entries = await _graph(request).scope_entries(program_id, active_only=active_only)
    return [scope_dict(s) for s in entries]


@router.post("/programs/{program_id}/scope", status_code=201,
             dependencies=[Depends(require_write)])
async def add_scope(request: Request, program_id: str, body: ScopeEntryCreate) -> dict[str, Any]:
    await _require_program(request, program_id)
    try:
        entry = await _graph(request).add_scope_entry(
            program_id, body.value, entry_type=body.entry_type, kind=body.kind,
            ports=body.ports, protocols=body.protocols, added_by="api",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return scope_dict(entry)


# --------------------------------------------------------------------- assets
@router.get("/programs/{program_id}/assets")
async def list_assets(request: Request, program_id: str, kind: str | None = None,
                      alive_only: bool = False) -> list[dict[str, Any]]:
    await _require_program(request, program_id)
    assets = await _graph(request).list_assets(program_id, kind=kind, alive_only=alive_only)
    return [asset_dict(a) for a in assets]


@router.post("/programs/{program_id}/assets", dependencies=[Depends(require_write)])
async def record_asset(request: Request, program_id: str, body: AssetRecord) -> dict[str, Any]:
    await _require_program(request, program_id)
    try:
        asset, is_new = await _graph(request).record_asset(
            program_id, body.kind, body.canonical_value, body.display_value,
            discovered_by=body.discovered_by, fingerprint=body.fingerprint,
            metadata=body.metadata,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"asset": asset_dict(asset), "is_new": is_new}


@router.get("/programs/{program_id}/endpoints")
async def list_endpoints(request: Request, program_id: str, asset_id: str | None = None,
                         limit: int | None = None) -> list[dict[str, Any]]:
    """A program's HTTP routes (from recon + imported Burp/Caido/HAR), juiciest-first."""
    await _require_program(request, program_id)
    eps = await _graph(request).list_endpoints(program_id, asset_id=asset_id, limit=limit)
    return [endpoint_dict(e) for e in eps]


# ------------------------------------------------------------------- findings
@router.get("/programs/{program_id}/findings")
async def list_findings(request: Request, program_id: str,
                        status: str | None = None) -> list[dict[str, Any]]:
    await _require_program(request, program_id)
    findings = await _graph(request).list_findings(program_id, status=status)
    return [finding_dict(f) for f in findings]


async def _require_finding(request: Request, program_id: str, finding_id: str):
    finding = await _graph(request).get_finding(finding_id)
    if finding is None or finding.program_id != program_id:
        raise HTTPException(status_code=404, detail=f"finding '{finding_id}' not found in this program")
    return finding


@router.patch("/programs/{program_id}/findings/{finding_id}",
              dependencies=[Depends(require_write)])
async def update_finding(request: Request, program_id: str, finding_id: str,
                         body: FindingUpdate) -> dict[str, Any]:
    await _require_program(request, program_id)
    await _require_finding(request, program_id, finding_id)
    graph = _graph(request)
    finding = None
    if body.status is not None:
        try:
            finding = await graph.set_finding_status(finding_id, body.status)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    other = {k: v for k, v in body.model_dump(exclude={"status"}).items() if v is not None}
    if other:
        finding = await graph.update_finding(finding_id, **other)
    if finding is None:                       # no fields supplied — return current state
        finding = await graph.get_finding(finding_id)
    return finding_dict(finding)


@router.get("/programs/{program_id}/findings/{finding_id}/report")
async def finding_report(request: Request, program_id: str, finding_id: str,
                         platform: str = "generic") -> dict[str, Any]:
    program = await _require_program(request, program_id)
    finding = await _require_finding(request, program_id, finding_id)
    from orthrus.model.report import render_program_finding
    markdown = render_program_finding(finding, platform=platform, program_name=program.name)
    return {"platform": platform, "finding_id": finding_id, "markdown": markdown}


@router.get("/programs/{program_id}/cost")
async def program_cost(request: Request, program_id: str) -> dict[str, Any]:
    await _require_program(request, program_id)
    return await _graph(request).cost_summary(program_id)


# ---------------------------------------------------------------------- notes
@router.get("/programs/{program_id}/notes")
async def list_notes(request: Request, program_id: str, q: str | None = None) -> list[dict[str, Any]]:
    await _require_program(request, program_id)
    graph = _graph(request)
    notes = (await graph.search_notes(q, program_id=program_id) if q
             else await graph.list_notes(program_id=program_id))
    return [note_dict(n) for n in notes]


@router.post("/programs/{program_id}/notes", status_code=201,
             dependencies=[Depends(require_write)])
async def create_note(request: Request, program_id: str, body: NoteCreate) -> dict[str, Any]:
    await _require_program(request, program_id)
    try:
        note = await _graph(request).add_note(
            body.title, body.markdown, program_id=program_id, tags=body.tags,
            finding_id=body.finding_id, asset_id=body.asset_id, created_by="api")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return note_dict(note)


@router.delete("/programs/{program_id}/notes/{note_id}", dependencies=[Depends(require_write)])
async def delete_note(request: Request, program_id: str, note_id: str) -> dict[str, Any]:
    await _require_program(request, program_id)
    if not await _graph(request).delete_note(note_id):
        raise HTTPException(status_code=404, detail=f"note '{note_id}' not found")
    return {"deleted": note_id}


# -------------------------------------------------------------------- copilot
@router.post("/programs/{program_id}/copilot")
async def copilot(request: Request, program_id: str, body: CopilotQuery) -> dict[str, Any]:
    """Grounded retrieval over the program's OWN findings + notes (cites, never invents)."""
    await _require_program(request, program_id)
    from orthrus.model.copilot import retrieve
    hits = await retrieve(_graph(request), program_id, body.query, k=body.k)
    return {
        "query": body.query,
        "hits": [{"source": h.source, "title": h.title, "snippet": h.snippet, "score": h.score}
                 for h in hits],
    }


# ----------------------------------------------------------------------- plan
@router.get("/programs/{program_id}/plan")
async def program_plan(request: Request, program_id: str) -> dict[str, Any]:
    """Ranked next actions grounded in the program's graph state (deterministic)."""
    program = await _require_program(request, program_id)
    from orthrus.model.planner import next_actions
    actions = await next_actions(_graph(request), program_id, program_name=program.name)
    return {"actions": [{"key": a.key, "priority": a.priority,
                         "reason": a.reason, "command": a.command} for a in actions]}


# --------------------------------------------------------------------- audit
@router.get("/audit/verify")
async def verify_audit(request: Request) -> dict[str, Any]:
    ok, first_bad = await _graph(request).verify_audit()
    return {"intact": ok, "first_bad_id": first_bad}


__all__ = ["router", "require_write"]
