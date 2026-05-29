"""SARIF 2.1.0 report output: structure, severity mapping, rule dedup, taxonomy
tags, and result fingerprints (CI dashboards consume this format)."""

from __future__ import annotations

import json

from orthrus.core.schemas import Confidence, Finding, ParamLocation, Severity
from orthrus.db.store import Store
from orthrus.reporting.generator import (
    _build_context,
    _cwe_tag,
    _finding_fingerprint,
    _rule_name,
    _security_severity,
    _write_sarif,
)


def _read_json(path: str) -> dict:
    # A sync reader keeps the blocking open() out of the async test (ruff ASYNC230).
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# ------------------------------------------------------------- pure helpers
def test_rule_name_pascal_cases_vuln_type():
    assert _rule_name("sqli") == "Sqli"
    assert _rule_name("security-headers") == "SecurityHeaders"
    assert _rule_name("cmd_injection") == "CmdInjection"


def test_cwe_tag_normalizes_to_github_taxonomy():
    assert _cwe_tag("CWE-89") == "external/cwe/cwe-89"
    assert _cwe_tag("79") == "external/cwe/cwe-79"
    assert _cwe_tag(None) is None
    assert _cwe_tag("none") is None  # no digits -> no tag


def test_security_severity_uses_cvss_then_falls_back():
    assert _security_severity({"severity": "high", "cvss_score": 9.8}) == "9.8"
    # no score -> bucket fallback keyed off the qualitative severity
    assert _security_severity({"severity": "medium", "cvss_score": None}) == "5.0"


def test_finding_fingerprint_is_stable_and_discriminating():
    a = {"vuln_type": "sqli", "url": "http://h/x", "parameter": "id", "param_location": "query"}
    b = {"vuln_type": "sqli", "url": "http://h/x", "parameter": "id", "param_location": "query"}
    c = {"vuln_type": "sqli", "url": "http://h/y", "parameter": "id", "param_location": "query"}
    assert _finding_fingerprint(a) == _finding_fingerprint(b)
    assert _finding_fingerprint(a) != _finding_fingerprint(c)


# ------------------------------------------------------- end-to-end SARIF doc
async def test_sarif_document_structure(tmp_path):
    store = Store(f"sqlite+aiosqlite:///{(tmp_path / 'h.db').as_posix()}")
    await store.init()
    try:
        scan_id = "scan-1"
        await store.create_scan(scan_id, "http://target", {}, {})
        # Two SQLi findings (same vuln_type -> one dedup'd rule, two results) ...
        for param in ("id", "q"):
            await store.add_finding(
                scan_id,
                Finding(
                    vuln_type="sqli",
                    title="SQL injection",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    url=f"http://target/search?{param}=1",
                    parameter=param,
                    param_location=ParamLocation.QUERY,
                    cwe="CWE-89",
                    cvss_score=9.8,
                ),
            )
        # ... and a lower-severity finding of a different class.
        await store.add_finding(
            scan_id,
            Finding(
                vuln_type="security-headers",
                title="Missing security headers",
                severity=Severity.LOW,
                url="http://target/",
            ),
        )
        context = await _build_context(store, scan_id, None, None)
    finally:
        await store.close()

    doc = json.loads(_write_sarif(context))

    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "ORTHRUS"

    # Rules are deduplicated by vuln_type: {sqli, security-headers}.
    rules = run["tool"]["driver"]["rules"]
    assert {r["id"] for r in rules} == {"sqli", "security-headers"}
    sqli_rule = next(r for r in rules if r["id"] == "sqli")
    assert sqli_rule["name"] == "Sqli"
    assert "external/cwe/cwe-89" in sqli_rule["properties"]["tags"]
    assert sqli_rule["defaultConfiguration"]["level"] == "error"

    # One result per finding (3), each referencing a valid rule index.
    results = run["results"]
    assert len(results) == 3
    for res in results:
        assert results[0]["ruleId"] in {"sqli", "security-headers"}
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert res["partialFingerprints"]["orthrusFindingHash/v1"]

    sqli_results = [r for r in results if r["ruleId"] == "sqli"]
    assert len(sqli_results) == 2
    assert all(r["level"] == "error" for r in sqli_results)
    assert all(r["properties"]["security-severity"] == "9.8" for r in sqli_results)
    # distinct parameters -> distinct fingerprints
    fps = {r["partialFingerprints"]["orthrusFindingHash/v1"] for r in sqli_results}
    assert len(fps) == 2

    headers_result = next(r for r in results if r["ruleId"] == "security-headers")
    assert headers_result["level"] == "note"  # low severity -> note


async def test_generate_report_writes_sarif_file(tmp_path):
    from orthrus.reporting.generator import generate_report

    store = Store(f"sqlite+aiosqlite:///{(tmp_path / 'h.db').as_posix()}")
    await store.init()
    try:
        await store.create_scan("s", "http://t", {}, {})
        await store.add_finding(
            "s",
            Finding(vuln_type="xss", title="XSS", severity=Severity.MEDIUM, url="http://t/x"),
        )
        out = str(tmp_path / "report")
        path = await generate_report(store, "s", "sarif", out)
    finally:
        await store.close()

    assert path.endswith(".sarif")
    doc = _read_json(path)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"][0]["ruleId"] == "xss"
