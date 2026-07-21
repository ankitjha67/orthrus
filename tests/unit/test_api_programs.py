"""Operator-graph REST API (FastAPI) — Programs/scope/assets/findings CRUD."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from orthrus.api import create_app  # noqa: E402


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
