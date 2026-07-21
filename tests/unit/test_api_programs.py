"""Operator-graph REST API (FastAPI) - Programs/scope/assets/findings CRUD."""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from orthrus.api import create_app  # noqa: E402
from orthrus.model.store import ProgramGraph  # noqa: E402


@pytest.fixture
def client(tmp_path):
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'graph_api.sqlite3'}"
    with TestClient(create_app(db_url=db_url)) as c:
        yield c


def _make_program(client, **over):
    body = {"name": "Acme", "authorization_source": "https://hackerone.com/acme",
            "platform": "h1", **over}
    r = client.post("/api/programs", json=body)
    return r


def test_create_list_get_program(client):
    r = _make_program(client)
    assert r.status_code == 201
    pid = r.json()["id"]
    assert r.json()["name"] == "Acme" and r.json()["platform"] == "h1"

    assert [p["id"] for p in client.get("/api/programs").json()] == [pid]
    assert client.get(f"/api/programs/{pid}").json()["authorization_source"].startswith("https://")
    assert client.get("/api/programs/nope").status_code == 404


def test_create_program_deny_by_default(client):
    r = client.post("/api/programs", json={"name": "NoAuth", "authorization_source": ""})
    assert r.status_code == 400 and "authorization_source is required" in r.json()["detail"]
    r2 = client.post("/api/programs", json={"name": "Bad", "authorization_source": "x",
                                            "platform": "nope"})
    assert r2.status_code == 400 and "platform must be one of" in r2.json()["detail"]


def test_update_and_delete_program(client):
    pid = _make_program(client).json()["id"]
    r = client.patch(f"/api/programs/{pid}", json={"is_paused": True, "priority": 1})
    assert r.json()["is_paused"] is True and r.json()["priority"] == 1

    assert client.delete(f"/api/programs/{pid}").json() == {"deleted": pid}
    assert client.get(f"/api/programs/{pid}").status_code == 404
    assert client.delete(f"/api/programs/{pid}").status_code == 404


def test_scope_crud(client):
    pid = _make_program(client).json()["id"]
    r = client.post(f"/api/programs/{pid}/scope",
                    json={"value": "*.acme.com", "entry_type": "in", "kind": "domain"})
    assert r.status_code == 201 and r.json()["value"] == "*.acme.com"
    client.post(f"/api/programs/{pid}/scope", json={"value": "admin.acme.com", "entry_type": "out"})
    entries = client.get(f"/api/programs/{pid}/scope").json()
    assert {e["entry_type"] for e in entries} == {"in", "out"}

    bad = client.post(f"/api/programs/{pid}/scope", json={"value": "x", "kind": "bogus"})
    assert bad.status_code == 400


def test_asset_record_dedups(client):
    pid = _make_program(client).json()["id"]
    r1 = client.post(f"/api/programs/{pid}/assets",
                     json={"kind": "subdomain", "canonical_value": "api.acme.com"})
    assert r1.json()["is_new"] is True
    r2 = client.post(f"/api/programs/{pid}/assets",
                     json={"kind": "subdomain", "canonical_value": "api.acme.com"})
    assert r2.json()["is_new"] is False
    assert len(client.get(f"/api/programs/{pid}/assets").json()) == 1


def test_findings_cost_audit_endpoints(client):
    pid = _make_program(client).json()["id"]
    assert client.get(f"/api/programs/{pid}/findings").json() == []
    assert client.get(f"/api/programs/{pid}/cost").json()["entries"] == 0
    assert client.get("/api/audit/verify").json()["intact"] is True


def test_endpoints_and_plan_endpoints(client, tmp_path):
    pid = _make_program(client).json()["id"]
    client.post(f"/api/programs/{pid}/scope",
                json={"value": "acme.com", "entry_type": "in", "kind": "domain"})
    # empty program still plans (recon, since it's scoped) and lists no endpoints
    assert client.get(f"/api/programs/{pid}/endpoints").json() == []
    plan = client.get(f"/api/programs/{pid}/plan").json()["actions"]
    assert plan and plan[0]["key"] == "recon"

    # record an asset (via API) + an endpoint (via a separate graph on the same file DB)
    aid = client.post(f"/api/programs/{pid}/assets",
                      json={"kind": "subdomain",
                            "canonical_value": "api.acme.com"}).json()["asset"]["id"]

    async def _add():
        g = ProgramGraph(f"sqlite+aiosqlite:///{tmp_path / 'graph_api.sqlite3'}")
        await g.init()
        await g.record_endpoint(aid, "/v1/login", method="POST",
                                body_params=["u", "p"], juicy_score=0.9)
        await g.close()
    asyncio.run(_add())

    eps = client.get(f"/api/programs/{pid}/endpoints").json()
    assert len(eps) == 1 and eps[0]["path"] == "/v1/login" and eps[0]["juicy_score"] == 0.9
    assert client.get("/api/programs/nope/plan").status_code == 404


def test_attack_chains_endpoints(client, tmp_path):
    pid = _make_program(client).json()["id"]
    # seed a chainable pair (SSRF + exposed-service) via a separate graph on the same DB
    async def _seed():
        g = ProgramGraph(f"sqlite+aiosqlite:///{tmp_path / 'graph_api.sqlite3'}")
        await g.init()
        await g.record_finding(pid, "ssrf", "SSRF", "high", "s-ssrf")
        await g.record_finding(pid, "exposed-service", "Exposed", "high", "s-exp")
        await g.close()
    asyncio.run(_seed())

    assert client.get(f"/api/programs/{pid}/chains").json() == []
    corr = client.post(f"/api/programs/{pid}/chains/correlate").json()
    assert corr["created"] == 1
    chains = client.get(f"/api/programs/{pid}/chains").json()
    assert len(chains) == 1 and chains[0]["relationship"] == "enables"
    assert chains[0]["proposed_by"] == "rules"


def test_write_gate_requires_token_when_configured(client, monkeypatch):
    monkeypatch.setenv("ORTHRUS_API_TOKEN", "s3cret")
    # mutation without the token is refused
    assert _make_program(client).status_code == 401
    # reads stay open
    assert client.get("/api/programs").status_code == 200
    # with the token it succeeds
    r = client.post("/api/programs", json={"name": "Acme", "authorization_source": "self-owned-lab",
                                           "platform": "self"},
                    headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 201
