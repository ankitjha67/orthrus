"""Big-Four-grade AI report writer - grounded assembly, dry-run, CLI."""

from __future__ import annotations

import asyncio

from click.testing import CliRunner

from orthrus import main
from orthrus.ai.providers import LLMError
from orthrus.ai.report_writer import write_consultant_report
from orthrus.core.schemas import Evidence, Finding, Severity
from orthrus.db.store import Store


def _finding(**over) -> dict:
    f = {
        "id": 1, "vuln_type": "sqli", "title": "SQL injection in 'id'", "severity": "critical",
        "confidence": "confirmed", "url": "http://t/item?id=1", "parameter": "id",
        "cwe": "CWE-89", "owasp": "A03:2021 Injection",
        "attack": [{"id": "T1190", "name": "Exploit Public-Facing Application", "url": "u"}],
        "d3fend": [{"id": "D3-ITF", "name": "Inbound Traffic Filtering"}],
        "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N", "cvss_v4_score": 9.3, "cvss_v4_vector": "CVSS:4.0/AV:N",
        "epss": 0.42, "scanner": "sqli", "description": "Error-based SQLi.",
        "remediation": "Use parameterized queries.",
        "evidence": {"request_raw": "GET /item?id=1'-- HTTP/1.1", "response_raw": "HTTP/1.1 500 SQL syntax error",
                     "matched_at": "you have an error in your SQL syntax", "notes": ""},
        "exploitations": [{"technique": "sqli-replay", "success": True, "extracted_data": "admin@x",
                           "request_raw": "GET /item?id=1'--", "callback_id": None}],
    }
    f.update(over)
    return f


def _ctx(findings=None, chains=None) -> dict:
    findings = findings if findings is not None else [_finding()]
    counts: dict = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {
        "generated_at": "2026-07-03 10:00 UTC",
        "scan": {"id": "scan-1", "target": "http://t", "status": "completed",
                 "started_at": "2026-07-03T09:00:00", "completed_at": "2026-07-03T09:30:00",
                 "scope": {"domains": ["t"], "ip_ranges": []}},
        "summary": {"total": len(findings), "confirmed": sum(1 for f in findings if f["confidence"] == "confirmed"),
                    "counts": counts, "owasp_counts": {"A03:2021 Injection": 1}},
        "findings": findings, "top_findings": findings[:5],
        "chains": chains or [], "triage": {}, "branding": {"name": "ORTHRUS"},
    }


class _FakeClient:
    def __init__(self, text="AI-NARRATIVE-PROSE"):
        self.text = text
        self.calls = 0

    async def complete(self, system, user, *, max_tokens=None, temperature=None):
        self.calls += 1
        return self.text


class _DeadClient:
    async def complete(self, *a, **k):
        raise LLMError("model unavailable")


def _run(coro):
    return asyncio.run(coro)


# --- assembly -------------------------------------------------------------

def test_report_has_all_sections_and_embeds_evidence():
    client = _FakeClient()
    md = _run(write_consultant_report(_ctx(), client))
    for section in [
        "# Penetration Test Report", "### Document Control", "## Contents",
        "## 1. Executive Summary", "Overall risk rating", "## 2. Assessment Scope",
        "## 3. Findings Overview", "### 3.4 Key Findings Summary", "## 4. Detailed Findings",
        "#### References", "## 6. Remediation Plan & Roadmap", "### 6.1 Prioritised Remediation Plan",
        "## 7. Compliance", "## 8. Conclusion", "## 9. Appendices",
    ]:
        assert section in md, section
    # remediation plan table has the operational columns
    assert "Suggested Owner" in md and "Target Window" in md
    # deterministic metadata + verbatim evidence
    assert "SQL injection in 'id'" in md and "CVSS v3.1" in md and "T1190" in md
    assert "GET /item?id=1'-- HTTP/1.1" in md  # request recorded verbatim
    assert "HTTP/1.1 500 SQL syntax error" in md  # response recorded verbatim
    assert "sqli-replay" in md  # exploitation confirmation recorded
    # LLM narrative present, and it ran per section (exec + finding + roadmap ≥ 3 calls)
    assert "AI-NARRATIVE-PROSE" in md and client.calls >= 3


def test_dry_run_builds_scaffold_and_evidence_without_client():
    md = _run(write_consultant_report(_ctx(), None, dry_run=True))
    assert "# Penetration Test Report" in md
    assert "GET /item?id=1'-- HTTP/1.1" in md  # evidence still recorded
    assert "AI-NARRATIVE-PROSE" not in md  # no model output
    assert "dry-run" in md.lower() or "AI-generated" in md  # placeholder noted


def test_best_effort_falls_back_when_model_fails():
    md = _run(write_consultant_report(_ctx(), _DeadClient()))
    # report still completes; per-finding deterministic remediation used as fallback
    assert "# Penetration Test Report" in md and "Use parameterized queries." in md


def test_similar_findings_are_grouped_with_affected_table():
    # seven reflected-XSS findings that differ only by parameter -> ONE grouped finding
    xss = [
        _finding(id=i, vuln_type="xss", title=f"Reflected XSS in '{p}'", severity="high",
                 confidence="confirmed", url=f"http://t/s?{p}=1", parameter=p,
                 cvss_score=7.4, cwe="CWE-79", owasp="A03:2021 Injection")
        for i, p in enumerate(["q", "s", "ref", "name", "cb", "next", "lang"], 1)
    ]
    md = _run(write_consultant_report(_ctx(findings=xss), _FakeClient()))
    assert "Reflected XSS (7 instances)" in md
    assert "**Affected instances (7):**" in md
    assert "7 endpoints" in md  # key-findings summary shows endpoint count, not one URL
    # only one detailed entry (### 4.1), not seven
    assert "### 4.2" not in md
    # opting out restores per-instance entries
    ungrouped = _run(write_consultant_report(_ctx(findings=xss), _FakeClient(), group=False))
    assert "### 4.7" in ungrouped
    assert "Reflected XSS (7 instances)" not in ungrouped and "Affected instances" not in ungrouped


def test_attack_chain_section_rendered():
    chains = [{"name": "SQLi → data theft", "severity": "critical", "impact": "full DB read",
               "steps": [{"label": "SQL injection", "vuln_type": "sqli"}]}]
    md = _run(write_consultant_report(_ctx(chains=chains), _FakeClient()))
    assert "## 5. Correlated Attack Chains" in md and "SQLi → data theft" in md


# --- CLI (dry-run, no network) -------------------------------------------

def _db_url(tmp_path) -> str:
    return f"sqlite+aiosqlite:///{(tmp_path / 'h.db').as_posix()}"


def _seed(db_url: str) -> None:
    async def run():
        store = Store(db_url)
        await store.init()
        await store.create_scan("s", "http://t", {}, {})
        await store.add_finding("s", Finding(
            vuln_type="sqli", title="SQL injection", severity=Severity.CRITICAL, url="http://t/q",
            evidence=Evidence(request_raw="GET /q?id=1'-- HTTP/1.1", response_raw="HTTP/1.1 500 error")))
        await store.close()

    asyncio.run(run())


def test_cli_ai_report_dry_run(tmp_path, monkeypatch):
    _seed(_db_url(tmp_path))
    monkeypatch.setenv("ORTHRUS_DB_URL", _db_url(tmp_path))
    out = tmp_path / "consultant"
    r = CliRunner().invoke(
        main.cli, ["--no-banner", "ai-report", "--scan-id", "s", "--dry-run", "-o", str(out)]
    )
    assert r.exit_code == 0, r.output
    md = (tmp_path / "consultant.md").read_text(encoding="utf-8")
    assert "# Penetration Test Report" in md
    assert "GET /q?id=1'-- HTTP/1.1" in md  # recorded evidence in the deliverable


def test_cli_ai_report_html_format(tmp_path, monkeypatch):
    _seed(_db_url(tmp_path))
    monkeypatch.setenv("ORTHRUS_DB_URL", _db_url(tmp_path))
    out = tmp_path / "deliverable"
    r = CliRunner().invoke(
        main.cli,
        ["--no-banner", "ai-report", "--scan-id", "s", "--dry-run", "--format", "html", "-o", str(out)],
    )
    assert r.exit_code == 0, r.output
    html = (tmp_path / "deliverable.html").read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html and "<h1>Penetration Test Report" in html
    assert "<table>" in html  # rendered, not raw markdown
    assert not (tmp_path / "deliverable.md").exists()  # html format doesn't also write md


def test_cli_ai_report_unknown_scan(tmp_path, monkeypatch):
    _seed(_db_url(tmp_path))
    monkeypatch.setenv("ORTHRUS_DB_URL", _db_url(tmp_path))
    r = CliRunner().invoke(main.cli, ["--no-banner", "ai-report", "--scan-id", "nope", "--dry-run"])
    assert r.exit_code == 0  # graceful (logs error, writes nothing)
