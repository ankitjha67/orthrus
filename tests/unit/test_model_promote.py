"""Scan→graph finding promotion bridge (PRD §7.5, Phase 2)."""

from __future__ import annotations

import asyncio

from orthrus.core import schemas
from orthrus.model.promote import finding_signature, promote_findings
from orthrus.model.store import ProgramGraph


def _f(vt, sev, conf, url, title, **kw):
    return schemas.Finding(vuln_type=vt, title=title, severity=sev, confidence=conf,
                           url=url, scanner=vt, evidence=schemas.Evidence(), **kw)


def test_signature_is_class_host_title():
    a = _f("sqli", schemas.Severity.HIGH, schemas.Confidence.FIRM, "https://a.acme.com/x", "SQL injection")
    b = _f("sqli", schemas.Severity.HIGH, schemas.Confidence.FIRM, "https://a.acme.com/y", "SQL injection")
    c = _f("sqli", schemas.Severity.HIGH, schemas.Confidence.FIRM, "https://b.acme.com/x", "SQL injection")
    assert finding_signature(a) == finding_signature(b)     # same class+host+title
    assert finding_signature(a) != finding_signature(c)     # different host


def test_promote_maps_scores_and_dedups(tmp_path):
    async def run():
        g = ProgramGraph(f"sqlite+aiosqlite:///{(tmp_path / 'p.db').as_posix()}")
        await g.init()
        pid = (await g.create_program("Acme", "self-owned-lab", platform="self")).id
        run_row = await g.start_scan_run(pid, triggered_by="manual")

        findings = [
            _f("sqli", schemas.Severity.CRITICAL, schemas.Confidence.CONFIRMED,
               "https://a.acme.com/x", "SQL injection", cwe="CWE-89", cvss_score=9.8),
            _f("sqli", schemas.Severity.HIGH, schemas.Confidence.FIRM,
               "https://a.acme.com/y", "SQL injection"),                 # same signature → dup
            _f("xss", schemas.Severity.MEDIUM, schemas.Confidence.FIRM,
               "https://a.acme.com/z", "Reflected XSS"),
        ]
        counts = await promote_findings(g, pid, findings, scan_run_id=run_row.id)
        assert counts == {"seen": 3, "new": 2, "duplicate": 1}

        promoted = await g.list_findings(pid)
        assert {f.vuln_class for f in promoted} == {"sqli", "xss"}
        sqli = next(f for f in promoted if f.vuln_class == "sqli")
        assert sqli.confidence == "confirmed" and sqli.cwe_id == "CWE-89"
        assert sqli.scan_run_id == run_row.id
        assert sqli.priority_score and sqli.priority_score > 0
        # ranked so the confirmed critical leads
        assert promoted[0].vuln_class == "sqli"
        await g.close()

    asyncio.run(run())
