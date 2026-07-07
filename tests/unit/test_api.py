"""ORTHRUS REST API (FastAPI) — exercised via TestClient against a seeded DB."""

from __future__ import annotations

import asyncio

import pytest

from orthrus.core import schemas

pytest.importorskip("fastapi")  # API ships in the [api] extra
from fastapi.testclient import TestClient  # noqa: E402

from orthrus.api import create_app  # noqa: E402
from orthrus.db.store import Store  # noqa: E402


def _finding(
    vuln_type: str, severity: schemas.Severity, url: str = "https://example.com/x"
) -> schemas.Finding:
    return schemas.Finding(
        vuln_type=vuln_type,
        title=f"{vuln_type} finding",
        severity=severity,
        confidence=schemas.Confidence.FIRM,
        url=url,
        description="desc",
        remediation="fix it",
        scanner=vuln_type,
        evidence=schemas.Evidence(),
    )


@pytest.fixture
def client(tmp_path):
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'api.sqlite3'}"

    async def seed() -> None:
        store = Store(db_url)
        await store.init()
        await store.create_scan("scan-apitest", "https://example.com", {}, {})
        await store.add_finding("scan-apitest", _finding("sqli", schemas.Severity.HIGH))
        await store.add_finding("scan-apitest", _finding("xss", schemas.Severity.MEDIUM))
        await store.set_scan_status("scan-apitest", "completed", completed=True)
        # A second scan whose finding URL carries an XSS payload — the dashboard
        # must render it escaped (a security tool's own UI must not be XSS-able).
        await store.create_scan("scan-xss", "https://x.example", {}, {})
        await store.add_finding(
            "scan-xss",
            _finding("xss", schemas.Severity.HIGH, url="https://x/<script>alert(1)</script>"),
        )
        await store.set_scan_status("scan-xss", "completed", completed=True)
        await store.close()

    asyncio.run(seed())
    with TestClient(create_app(db_url=db_url)) as c:
        yield c


def test_health(client) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert "version" in r.json()


def test_list_scans(client) -> None:
    r = client.get("/api/scans")
    assert r.status_code == 200
    scans = r.json()
    assert any(s["id"] == "scan-apitest" and s["findings"] == 2 for s in scans)


def test_scan_detail_and_summary(client) -> None:
    r = client.get("/api/scans/scan-apitest")
    assert r.status_code == 200
    body = r.json()
    assert body["target"] == "https://example.com"
    assert body["status"] == "completed"
    assert body["summary"]["high"] == 1
    assert body["summary"]["medium"] == 1


def test_findings(client) -> None:
    r = client.get("/api/scans/scan-apitest/findings")
    assert r.status_code == 200
    findings = r.json()
    assert len(findings) == 2
    assert {f["vuln_type"] for f in findings} == {"sqli", "xss"}
    assert all("id" in f for f in findings)


def test_report_endpoint(client) -> None:
    r = client.get("/api/scans/scan-apitest/report")
    assert r.status_code == 200
    body = r.json()
    assert body["scan"]["id"] == "scan-apitest"
    assert len(body["findings"]) == 2
    assert "summary" in body


def test_unknown_scan_404(client) -> None:
    assert client.get("/api/scans/does-not-exist").status_code == 404
    assert client.get("/api/scans/does-not-exist/findings").status_code == 404


# ----------------------------------------------------------------- dashboard
def test_dashboard_index(client) -> None:
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "scan-apitest" in r.text
    assert "ORTHRUS" in r.text


def test_dashboard_scan_detail(client) -> None:
    r = client.get("/dashboard/scans/scan-apitest")
    assert r.status_code == 200
    assert "sqli" in r.text and "https://example.com" in r.text


def test_dashboard_escapes_xss_payload(client) -> None:
    # The finding URL contains <script>; the page must escape it, not emit it raw.
    r = client.get("/dashboard/scans/scan-xss")
    assert r.status_code == 200
    assert "<script>alert(1)</script>" not in r.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r.text


def test_dashboard_surface_route(client) -> None:
    r = client.get("/dashboard/scans/scan-apitest/surface")
    assert r.status_code == 200 and "<svg" in r.text and "example.com" in r.text


def test_replay_requires_a_url(client) -> None:
    assert client.post("/api/replay", json={}).status_code == 400


def test_replay_rejects_unscanned_host(client) -> None:
    # the browser Repeater is scope-gated to hosts that appear as a scan target
    r = client.post("/api/replay", json={"url": "http://evil.test/"})
    assert r.status_code == 403


def test_replay_allows_scanned_host(client, monkeypatch) -> None:
    from orthrus.api import app as app_mod
    from orthrus.proxy.replay import ReplayResult

    async def _fake(spec, validator, **kw):
        return ReplayResult(method=spec.method, url=spec.url, status=204, reason="No Content",
                            elapsed_ms=1.0)

    monkeypatch.setattr(app_mod, "_replay", _fake)
    r = client.post("/api/replay", json={"url": "https://example.com/x", "method": "GET"})
    assert r.status_code == 200 and r.json()["status"] == 204
