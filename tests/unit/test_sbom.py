"""Tests for the CycloneDX SBOM emitter."""

from __future__ import annotations

import json

from orthrus.risk.sbom import (
    Component,
    Vulnerability,
    build_sbom,
    components_from_technologies,
    write_sbom,
)

TS = "2026-01-01T00:00:00+00:00"


def test_component_ref_prefers_purl_then_name_version():
    assert Component("jquery", "1.12.4", purl="pkg:npm/jquery@1.12.4").ref() == "pkg:npm/jquery@1.12.4"
    assert Component("lodash", "4.17.4").ref() == "lodash@4.17.4"
    assert Component("nginx").ref() == "nginx"


def test_bom_has_required_cyclonedx_envelope():
    bom = build_sbom([Component("jquery", "1.12.4")], timestamp=TS, tool_version="0.1.0")
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert bom["version"] == 1
    assert bom["metadata"]["timestamp"] == TS
    assert bom["metadata"]["tools"][0]["name"] == "orthrus"


def test_components_are_deduped_and_sorted():
    comps = [Component("Zlib", "1.2"), Component("apache", "2.4"), Component("Zlib", "1.2")]
    bom = build_sbom(comps, timestamp=TS)
    names = [c["name"] for c in bom["components"]]
    assert names == ["apache", "Zlib"]        # sorted case-insensitively, deduped


def test_component_node_fields():
    bom = build_sbom([Component("jquery", "1.12.4", type="library", purl="pkg:npm/jquery@1.12.4",
                                cpe="cpe:2.3:a:jquery:jquery:1.12.4:*:*:*:*:*:*:*")], timestamp=TS)
    node = bom["components"][0]
    assert node["type"] == "library" and node["name"] == "jquery" and node["version"] == "1.12.4"
    assert node["bom-ref"] == "pkg:npm/jquery@1.12.4" and node["purl"] == "pkg:npm/jquery@1.12.4"
    assert node["cpe"].startswith("cpe:2.3:a:jquery")


def test_target_becomes_metadata_application_component():
    bom = build_sbom([], target="https://app.example.com", timestamp=TS)
    assert bom["metadata"]["component"] == {
        "type": "application", "bom-ref": "https://app.example.com", "name": "https://app.example.com",
    }


def test_vulnerabilities_link_to_component_refs():
    comp = Component("jquery", "1.12.4", purl="pkg:npm/jquery@1.12.4")
    vuln = Vulnerability("CVE-2020-11022", affects=comp.ref(), severity="Medium", source="NVD")
    bom = build_sbom([comp], timestamp=TS, vulnerabilities=[vuln])
    v = bom["vulnerabilities"][0]
    assert v["id"] == "CVE-2020-11022"
    assert v["affects"] == [{"ref": "pkg:npm/jquery@1.12.4"}]
    assert v["ratings"][0]["severity"] == "medium"        # normalised lower-case
    assert v["source"]["name"] == "NVD"


def test_no_vulnerabilities_key_when_none():
    assert "vulnerabilities" not in build_sbom([Component("nginx")], timestamp=TS)


def test_components_from_technologies_mapper():
    comps = components_from_technologies([
        {"name": "jQuery", "version": "1.12.4", "type": "library"},
        {"name": "", "version": "x"},          # skipped: no name
        {"name": "nginx"},
    ])
    assert [c.name for c in comps] == ["jQuery", "nginx"]
    assert comps[0].version == "1.12.4"


def test_is_deterministic_and_round_trips(tmp_path):
    comps = [Component("apache", "2.4"), Component("jquery", "1.12.4")]
    a = build_sbom(comps, timestamp=TS, target="t")
    b = build_sbom(list(reversed(comps)), timestamp=TS, target="t")
    assert a == b                              # order-independent
    out = tmp_path / "sbom.json"
    write_sbom(str(out), a)
    assert json.loads(out.read_text(encoding="utf-8"))["bomFormat"] == "CycloneDX"
