"""Operator-graph finding triage + report REST endpoints (PRD §7.5/§7.6)."""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from orthrus.api import create_app  # noqa: E402
from orthrus.model.store import ProgramGraph  # noqa: E402


@pytest.fixture
def client_ids(tmp_path):
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'findings_api.sqlite3'}"
    ids: dict[str, str] = {}

    async def seed():
        g = ProgramGraph(db_url)
        await g.init()
        p = await g.create_program("Acme", "self-owned-lab", platform="self")
        f, _ = await g.record_finding(
            p.id, "sqli", "SQL injection", "critical", "sig1",
            confidence="confirmed", found_by_tool="dalfox", cwe_id="CWE-89",
            cvss_v3_score=9.8, priority_score=95)
        ids["program"], ids["finding"] = p.id, f.id
        await g.close()

    asyncio.run(seed())
    with TestClient(create_app(db_url=db_url)) as c:
        yield c, ids


def test_list_findings(client_ids):
    c, ids = client_ids
    rows = c.get(f"/api/programs/{ids['program']}/findings").json()
    assert len(rows) == 1 and rows[0]["vuln_class"] == "sqli" and rows[0]["priority_score"] == 95


def test_patch_status_stamps_and_assign(client_ids):
    c, ids = client_ids
    r = c.patch(f"/api/programs/{ids['program']}/findings/{ids['finding']}",
                json={"status": "confirmed"})
    assert r.status_code == 200 and r.json()["status"] == "confirmed"

    r2 = c.patch(f"/api/programs/{ids['program']}/findings/{ids['finding']}",
                 json={"assigned_to": "me", "hunter_notes_md": "dupe of #12"})
    assert r2.status_code == 200

    bad = c.patch(f"/api/programs/{ids['program']}/findings/{ids['finding']}",
                  json={"status": "not-a-status"})
    assert bad.status_code == 400


def test_finding_report_endpoint(client_ids):
    c, ids = client_ids
    r = c.get(f"/api/programs/{ids['program']}/findings/{ids['finding']}/report",
              params={"platform": "hackerone"})
    assert r.status_code == 200
    body = r.json()
    assert body["platform"] == "hackerone"
    assert "CWE-89" in body["markdown"] and "# SQL injection" in body["markdown"]


def test_finding_404_when_not_in_program(client_ids):
    c, ids = client_ids
    r = c.patch(f"/api/programs/{ids['program']}/findings/nope", json={"status": "confirmed"})
    assert r.status_code == 404
    r2 = c.get(f"/api/programs/{ids['program']}/findings/nope/report")
    assert r2.status_code == 404


def test_copilot_retrieves_from_own_findings(client_ids):
    c, ids = client_ids
    r = c.post(f"/api/programs/{ids['program']}/copilot", json={"query": "SQL injection"})
    assert r.status_code == 200
    hits = r.json()["hits"]
    assert hits and hits[0]["source"].startswith("finding:")
    # grounded: an unrelated query returns nothing rather than inventing
    empty = c.post(f"/api/programs/{ids['program']}/copilot", json={"query": "zzqx-not-a-thing"})
    assert empty.json()["hits"] == []
