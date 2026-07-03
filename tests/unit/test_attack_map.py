"""MITRE ATT&CK / D3FEND mapping + ATT&CK Navigator layer export."""

from __future__ import annotations

import asyncio
import json

from click.testing import CliRunner

from orthrus import main
from orthrus.core.schemas import Finding, Severity
from orthrus.db.store import Store
from orthrus.reporting.attack_map import (
    attack_for,
    attack_ids,
    build_navigator_layer,
    d3fend_for,
)

# --- mapping --------------------------------------------------------------

def test_attack_ids_known_and_default():
    assert "T1190" in attack_ids("sqli")
    assert attack_ids("totally-unknown") == ["T1190"]  # sensible default


def test_attack_aliases_normalize():
    # reflected/dom/stored xss all resolve to the xss technique set (incl JS execution).
    assert "T1059.007" in attack_ids("reflected-xss")
    assert attack_ids("dom-xss") == attack_ids("stored-xss") == attack_ids("xss")


def test_attack_for_is_structured_with_names_and_urls():
    techs = attack_for("jwt")
    ids = {t["id"] for t in techs}
    assert "T1550" in ids
    t = next(t for t in techs if t["id"] == "T1550")
    assert t["name"] and t["url"].startswith("https://attack.mitre.org/techniques/T1550")


def test_d3fend_minimal_confident_set():
    assert d3fend_for("jwt") == [{"id": "D3-MFA", "name": "Multi-factor Authentication"}]
    assert d3fend_for("sqli") == [{"id": "D3-ITF", "name": "Inbound Traffic Filtering"}]
    assert d3fend_for("security-headers") == []  # no fabricated mapping


# --- navigator layer ------------------------------------------------------

def _f(vt: str):
    return {"vuln_type": vt}


def test_navigator_layer_shape_and_scoring():
    findings = [_f("sqli"), _f("sqli"), _f("xxe"), _f("jwt")]
    layer = build_navigator_layer(findings, name="test")
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    by_id = {t["techniqueID"]: t for t in layer["techniques"]}
    # T1190 is enabled by sqli(x2) + xxe(x1) → score 3.
    assert by_id["T1190"]["score"] == 3
    assert "sqli" in by_id["T1190"]["comment"] and "xxe" in by_id["T1190"]["comment"]
    assert layer["gradient"]["maxValue"] == 3


def test_navigator_excludes_atlas_techniques():
    # prompt-injection maps to ATLAS AML.T0051, which is not an enterprise-attack ID.
    layer = build_navigator_layer([_f("prompt-injection")], name="t")
    assert all(not t["techniqueID"].startswith("AML.") for t in layer["techniques"])


# --- end-to-end report format --------------------------------------------

def _db_url(tmp_path) -> str:
    return f"sqlite+aiosqlite:///{(tmp_path / 'h.db').as_posix()}"


def _seed(db_url: str) -> None:
    async def run():
        store = Store(db_url)
        await store.init()
        await store.create_scan("s", "http://t", {}, {})
        for vt, title in [("sqli", "SQL injection"), ("xss", "Reflected XSS"), ("jwt", "Weak JWT")]:
            await store.add_finding(
                "s", Finding(vuln_type=vt, title=title, severity=Severity.HIGH, url="http://t/x"))
        await store.close()

    asyncio.run(run())


def test_report_navigator_format(tmp_path, monkeypatch):
    _seed(_db_url(tmp_path))
    monkeypatch.setenv("ORTHRUS_DB_URL", _db_url(tmp_path))
    out = tmp_path / "layer"
    r = CliRunner().invoke(
        main.cli, ["--no-banner", "report", "--scan-id", "s", "--format", "navigator", "-o", str(out)]
    )
    assert r.exit_code == 0, r.output
    # _emit writes with a .json extension for the navigator layer.
    layer = json.loads((tmp_path / "layer.json").read_text(encoding="utf-8"))
    assert layer["domain"] == "enterprise-attack"
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert {"T1190", "T1059.007", "T1550"} <= ids  # sqli, xss(JS), jwt techniques present


def test_report_json_includes_structured_attack(tmp_path, monkeypatch):
    _seed(_db_url(tmp_path))
    monkeypatch.setenv("ORTHRUS_DB_URL", _db_url(tmp_path))
    out = tmp_path / "rep"
    r = CliRunner().invoke(
        main.cli, ["--no-banner", "report", "--scan-id", "s", "--format", "json", "-o", str(out)]
    )
    assert r.exit_code == 0, r.output
    data = json.loads((tmp_path / "rep.json").read_text(encoding="utf-8"))
    sqli = next(f for f in data["findings"] if f["vuln_type"] == "sqli")
    assert any(t["id"] == "T1190" for t in sqli["attack"])
    assert sqli["d3fend"] == [{"id": "D3-ITF", "name": "Inbound Traffic Filtering"}]
