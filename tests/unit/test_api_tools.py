"""Workbench REST tools - Repeater (/tools/replay) + Intruder (/tools/intruder)."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from orthrus.api import create_app  # noqa: E402


@pytest.fixture
def client(tmp_path):
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'tools.sqlite3'}"
    with TestClient(create_app(db_url=db_url)) as c:
        yield c


def test_replay_blocks_out_of_scope(client):
    # scope is example.com; the request targets evil.test -> blocked before any send
    r = client.post("/api/tools/replay", json={
        "raw_request": "GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n",
        "scope": "example.com",
    })
    assert r.status_code == 200
    assert "out of scope" in (r.json()["error"] or "")


def test_replay_rejects_malformed_request(client):
    r = client.post("/api/tools/replay", json={"raw_request": "", "scope": "example.com"})
    assert r.status_code == 400


def test_intruder_validates_before_sending(client):
    # clusterbomb over 3x3 positions = 9 requests > max_requests(4) -> 400, no traffic
    r = client.post("/api/tools/intruder", json={
        "raw_request": "GET /?a=§1§&b=§2§ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "payloads": [["x", "y", "z"], ["1", "2", "3"]],
        "mode": "clusterbomb", "scope": "example.com", "max_requests": 4,
    })
    assert r.status_code == 400 and "exceeds" in r.json()["detail"]

    # unbalanced markers -> 400
    bad = client.post("/api/tools/intruder", json={
        "raw_request": "GET /?a=§1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "payloads": [["x"]], "mode": "sniper", "scope": "example.com",
    })
    assert bad.status_code == 400


def test_tools_are_write_gated(client, monkeypatch):
    monkeypatch.setenv("ORTHRUS_API_TOKEN", "s3cret")
    denied = client.post("/api/tools/replay", json={
        "raw_request": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "scope": "example.com"})
    assert denied.status_code == 401
    ok = client.post("/api/tools/replay", json={
        "raw_request": "GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n", "scope": "example.com"},
        headers={"Authorization": "Bearer s3cret"})
    assert ok.status_code == 200 and "out of scope" in (ok.json()["error"] or "")
