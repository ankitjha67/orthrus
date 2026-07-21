"""Operator-graph Notes REST endpoints (PRD §7.13)."""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from orthrus.api import create_app  # noqa: E402
from orthrus.model.store import ProgramGraph  # noqa: E402


@pytest.fixture
def client_pid(tmp_path):
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'notes_api.sqlite3'}"
    holder: dict[str, str] = {}

    async def seed():
        g = ProgramGraph(db_url)
        await g.init()
        holder["pid"] = (await g.create_program("Acme", "self-owned-lab", platform="self")).id
        await g.close()

    asyncio.run(seed())
    with TestClient(create_app(db_url=db_url)) as c:
        yield c, holder["pid"]


def test_note_crud_over_http(client_pid):
    c, pid = client_pid
    r = c.post(f"/api/programs/{pid}/notes",
               json={"title": "WAF bypass", "markdown": "json body trick", "tags": ["waf"]})
    assert r.status_code == 201
    nid = r.json()["id"]

    assert len(c.get(f"/api/programs/{pid}/notes").json()) == 1
    assert len(c.get(f"/api/programs/{pid}/notes", params={"q": "json"}).json()) == 1
    assert c.get(f"/api/programs/{pid}/notes", params={"q": "zzz"}).json() == []

    assert c.delete(f"/api/programs/{pid}/notes/{nid}").json() == {"deleted": nid}
    assert c.get(f"/api/programs/{pid}/notes").json() == []


def test_note_validation_and_404(client_pid):
    c, pid = client_pid
    assert c.post(f"/api/programs/{pid}/notes", json={"title": "  "}).status_code == 400
    assert c.delete(f"/api/programs/{pid}/notes/nope").status_code == 404
    assert c.get("/api/programs/nosuch/notes").status_code == 404
