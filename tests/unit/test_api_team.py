"""Team/RBAC REST surface — users, API keys, per-program membership (PRD §9)."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from orthrus.api import create_app  # noqa: E402


@pytest.fixture
def client(tmp_path):
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'team_api.sqlite3'}"
    with TestClient(create_app(db_url=db_url)) as c:
        yield c


def _program(client) -> str:
    return client.post("/api/programs", json={
        "name": "Acme", "authorization_source": "self-owned-lab", "platform": "self"}).json()["id"]


def test_user_lifecycle_and_me(client):
    u = client.post("/api/users", json={"email": "lead@acme.test", "name": "Lead"})
    assert u.status_code == 201 and u.json()["email"] == "lead@acme.test"
    assert u.json()["has_api_key"] is False
    uid = u.json()["id"]

    # duplicate email → 400
    assert client.post("/api/users", json={"email": "lead@acme.test"}).status_code == 400

    # mint a key, then /me resolves the caller
    key = client.post(f"/api/users/{uid}/api-key").json()["api_key"]
    me = client.get("/api/me", headers={"Authorization": f"Bearer {key}"})
    assert me.status_code == 200 and me.json()["id"] == uid
    assert client.get("/api/me", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.post("/api/users/nope/api-key").status_code == 404


def test_membership_and_role_enforcement(client, monkeypatch):
    pid = _program(client)
    owner = client.post("/api/users", json={"email": "owner@acme.test"}).json()["id"]
    viewer = client.post("/api/users", json={"email": "viewer@acme.test"}).json()["id"]
    owner_key = client.post(f"/api/users/{owner}/api-key").json()["api_key"]
    viewer_key = client.post(f"/api/users/{viewer}/api-key").json()["api_key"]

    # seed the owner membership via the shared admin path (no members yet → token gate)
    r = client.post(f"/api/programs/{pid}/members", json={"user_id": owner, "role": "owner"})
    assert r.status_code == 201 and r.json()["role"] == "owner"

    # now enforce RBAC: turn on the shared token so only it OR a program owner can manage
    monkeypatch.setenv("ORTHRUS_API_TOKEN", "admintok")

    # the owner (via their user key) can add a viewer
    add = client.post(f"/api/programs/{pid}/members", json={"user_id": viewer, "role": "viewer"},
                      headers={"Authorization": f"Bearer {owner_key}"})
    assert add.status_code == 201 and add.json()["email"] == "viewer@acme.test"

    # the viewer cannot manage members (needs owner) → 403
    denied = client.post(f"/api/programs/{pid}/members", json={"user_id": owner, "role": "member"},
                         headers={"Authorization": f"Bearer {viewer_key}"})
    assert denied.status_code == 403

    # but the viewer CAN read the member list (viewer role suffices)
    members = client.get(f"/api/programs/{pid}/members",
                         headers={"Authorization": f"Bearer {viewer_key}"})
    assert members.status_code == 200
    assert {m["email"] for m in members.json()} == {"owner@acme.test", "viewer@acme.test"}

    # no credentials at all → 401
    assert client.get(f"/api/programs/{pid}/members").status_code == 401

    # the shared admin token overrides everything (bootstrap / backward compat)
    revoke = client.delete(f"/api/programs/{pid}/members/{viewer}",
                           headers={"Authorization": "Bearer admintok"})
    assert revoke.status_code == 200 and revoke.json() == {"removed": viewer}
