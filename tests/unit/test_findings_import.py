"""Findings importer - Caido/Burp/SARIF/ORTHRUS/generic parsers + graph fold."""

from __future__ import annotations

import asyncio
import json

import pytest

from orthrus.bridges.findings_import import (
    detect_findings_format,
    fold_findings,
    parse_burp_issues,
    parse_caido_findings,
    parse_generic_json,
    parse_orthrus_findings,
    parse_sarif,
)
from orthrus.model.store import ProgramGraph

SARIF = json.dumps({
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "semgrep"}},
        "results": [{
            "ruleId": "python.lang.security.dangerous-exec",
            "level": "error",
            "message": {"text": "Detected exec() with user input (CWE-95)."},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "app/views.py"}, "region": {"startLine": 12}}}],
            "properties": {"cwe": ["CWE-95"]},
        }],
    }],
})

BURP = """<issues>
  <issue>
    <name>Cross-site scripting (reflected)</name>
    <host>https://t.test</host><path>/search</path>
    <severity>High</severity><confidence>Certain</confidence>
    <issueBackground>Reflected input in &lt;b&gt;response&lt;/b&gt;.</issueBackground>
    <vulnerabilityClassifications>CWE-79: Improper Neutralization</vulnerabilityClassifications>
  </issue>
  <issue>
    <name>Information disclosure</name><host>https://t.test</host><path>/debug</path>
    <severity>Information</severity><confidence>Tentative</confidence>
  </issue>
</issues>"""

CAIDO = json.dumps([
    {"title": "IDOR on /account", "severity": "high", "confidence": "firm",
     "url": "https://t.test/account?id=7", "description": "object id enumerable"},
    {"name": "Open redirect", "request": {"host": "t.test", "path": "/go"}},
])


def test_parse_sarif():
    fs = parse_sarif(SARIF)
    assert len(fs) == 1
    f = fs[0]
    assert f.tool == "semgrep" and f.severity == "high"        # error -> high
    assert f.location == "app/views.py:12"
    assert f.cwe == "CWE-95"
    assert parse_sarif("not json") == []


def test_parse_burp_issues_severity_confidence_and_xxe():
    fs = parse_burp_issues(BURP)
    assert len(fs) == 2
    xss = next(f for f in fs if "scripting" in f.title.lower())
    assert xss.vuln_class == "xss" and xss.severity == "high" and xss.confidence == "confirmed"
    assert xss.location == "https://t.test/search" and xss.cwe == "CWE-79"
    info = next(f for f in fs if "disclosure" in f.title.lower())
    assert info.severity == "info" and info.confidence == "tentative"

    from orthrus.bridges.burp import UnsafeXmlError
    with pytest.raises(UnsafeXmlError):
        parse_burp_issues('<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><issues/>')
    assert parse_burp_issues("not xml") == []


def test_parse_caido_and_orthrus_and_generic():
    caido = parse_caido_findings(CAIDO)
    assert len(caido) == 2
    idor = next(f for f in caido if "IDOR" in f.title)
    assert idor.vuln_class == "idor" and idor.severity == "high"
    assert caido[1].location == "https://t.test/go"          # built from request host+path

    orth = parse_orthrus_findings(json.dumps({"findings": [
        {"vuln_type": "ssrf", "title": "SSRF", "severity": "critical",
         "confidence": "confirmed", "url": "https://t.test/fetch", "cwe": "CWE-918"}]}))
    assert orth[0].vuln_class == "ssrf" and orth[0].confidence == "confirmed"

    gen = parse_generic_json(json.dumps([{"name": "thing", "level": "warning", "path": "/x"}]))
    assert gen[0].severity == "medium" and gen[0].location == "/x"


def test_format_detection():
    assert detect_findings_format(SARIF, "out.sarif") == "sarif"
    assert detect_findings_format(BURP, "issues.xml") == "burp"
    assert detect_findings_format(SARIF, "x.json") == "sarif"       # by content
    assert detect_findings_format('{"findings":[{"vuln_type":"x"}]}', "r.json") == "orthrus"
    assert detect_findings_format(CAIDO, "c.json") == "caido"


def test_fold_findings_into_graph(tmp_path):
    async def run():
        g = ProgramGraph(f"sqlite+aiosqlite:///{(tmp_path / 'f.db').as_posix()}")
        await g.init()
        pid = (await g.create_program("Acme", "self-owned-lab", platform="self")).id

        findings = parse_burp_issues(BURP)
        res = await fold_findings(g, pid, findings, source="burp",
                                  in_scope=lambda h: h == "t.test")
        assert res.total == 2 and res.new == 2
        stored = await g.list_findings(pid)
        assert len(stored) == 2
        assert all(f.priority_score is not None for f in stored)     # scored on import
        assert any(f.severity == "high" and f.vuln_class == "xss" for f in stored)

        # re-import is idempotent (dedup by signature)
        res2 = await fold_findings(g, pid, findings, source="burp")
        assert res2.new == 0 and res2.seen == 2
        assert len(await g.list_findings(pid)) == 2

        # out-of-scope finding is refused
        from orthrus.bridges.findings_import import ImportedFinding
        oos = [ImportedFinding(vuln_class="xss", title="x", severity="high",
                               location="https://evil.test/x")]
        res3 = await fold_findings(g, pid, oos, in_scope=lambda h: h == "t.test")
        assert res3.skipped_out_of_scope == 1 and res3.new == 0
        await g.close()

    asyncio.run(run())
