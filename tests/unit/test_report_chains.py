"""Report integration: attack-path chains + triage render into the deliverable."""

from __future__ import annotations

import json

from orthrus.core.schemas import Finding, Severity
from orthrus.db.store import Store
from orthrus.reporting.generator import (
    CHAIN_RULE_ID,
    _build_context,
    _render_html,
    _write_markdown,
    _write_sarif,
)


def _f(vuln_type, url, sev=Severity.HIGH):
    return Finding(vuln_type=vuln_type, title=f"{vuln_type} issue", severity=sev, url=url)


async def _seed():
    store = Store("sqlite+aiosqlite:///:memory:")
    await store.init()
    await store.create_scan("r", "https://app.test/", {}, {})
    for f in [
        _f("ssrf", "https://app.test/import?url=x"),
        _f("exposed-service", "https://app.test:6379/"),  # cross-port chain
        _f("idor", "https://app.test/order/1"),
        _f("idor", "https://app.test/order/2"),            # dup → triage folds
    ]:
        await store.add_finding("r", f)
    return store


async def test_context_includes_chains_and_triage():
    store = await _seed()
    try:
        ctx = await _build_context(store, "r", None, None)
    finally:
        await store.close()
    names = {c["name"] for c in ctx["chains"]}
    assert "SSRF → internal-service compromise" in names
    assert ctx["triage"]["collapsed"] == 1   # 2 IDOR → 1


async def test_technical_html_and_markdown_render_attack_paths():
    store = await _seed()
    try:
        ctx = await _build_context(store, "r", None, None)
    finally:
        await store.close()
    html = _render_html(ctx, "technical.html")
    exec_html = _render_html(ctx, "executive.html")
    md = _write_markdown(ctx)
    assert "Attack Paths" in html and "SSRF → internal-service compromise" in html
    assert "Attack Paths" in exec_html
    assert "## Attack Paths" in md
    assert "duplicate finding(s) folded" in md


async def test_sarif_emits_chain_as_codeflow():
    store = await _seed()
    try:
        ctx = await _build_context(store, "r", None, None)
    finally:
        await store.close()
    sarif = json.loads(_write_sarif(ctx))
    run = sarif["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert CHAIN_RULE_ID in rule_ids  # synthetic attack-path rule present

    chain_results = [r for r in run["results"] if r["ruleId"] == CHAIN_RULE_ID]
    assert len(chain_results) >= 1
    res = chain_results[0]
    assert res["level"] == "error"  # critical chain
    # the steps populate a SARIF codeFlow (ordered walk-through)
    locs = res["codeFlows"][0]["threadFlows"][0]["locations"]
    assert len(locs) == 2  # ssrf → exposed-service
    assert "Step 1" in locs[0]["location"]["message"]["text"]
    assert res["properties"]["attack-path"] is True
    assert float(res["properties"]["security-severity"]) >= 9.0  # critical


async def test_sarif_has_no_chain_rule_without_chains():
    store = Store("sqlite+aiosqlite:///:memory:")
    await store.init()
    await store.create_scan("r3", "https://app.test/", {}, {})
    await store.add_finding("r3", _f("security-headers", "https://app.test/", Severity.LOW))
    try:
        ctx = await _build_context(store, "r3", None, None)
    finally:
        await store.close()
    sarif = json.loads(_write_sarif(ctx))
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert CHAIN_RULE_ID not in rule_ids


async def test_report_with_no_chains_is_clean():
    store = Store("sqlite+aiosqlite:///:memory:")
    await store.init()
    await store.create_scan("r2", "https://app.test/", {}, {})
    await store.add_finding("r2", _f("security-headers", "https://app.test/", Severity.LOW))
    try:
        ctx = await _build_context(store, "r2", None, None)
    finally:
        await store.close()
    assert ctx["chains"] == []
    html = _render_html(ctx, "technical.html")
    assert "Attack Paths" not in html  # section omitted when there are no chains
