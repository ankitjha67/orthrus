"""CycloneDX SBOM emitter (Glasswing MTTA "inventory freshness").

A living Software Bill of Materials is the first MTTA dimension - "how current and
complete your view is of code, configuration and dependencies." ORTHRUS's recon
already fingerprints technologies and its SCA scanner detects component versions
(and their known CVEs); this turns that into a standard, machine-readable
**CycloneDX 1.5** document that downstream tooling (dependency-track, vuln feeds,
compliance) can ingest, with detected CVEs linked to the components they affect.

Pure and deterministic: components are deduped and sorted, and the timestamp is
injected by the caller, so the same inventory always serialises identically.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

SPEC_VERSION = "1.5"


@dataclass(frozen=True)
class Component:
    name: str
    version: str = ""
    type: str = "library"     # library | framework | application | operating-system | ...
    purl: str = ""            # package URL, when the ecosystem is known
    cpe: str = ""

    def ref(self) -> str:
        """A stable bom-ref: the purl if known, else name@version."""
        if self.purl:
            return self.purl
        return f"{self.name}@{self.version}" if self.version else self.name


@dataclass(frozen=True)
class Vulnerability:
    id: str                   # CVE-... / GHSA-...
    affects: str              # the bom-ref of the affected component
    severity: str = ""        # critical | high | medium | low | info
    source: str = "NVD"


def _component_node(c: Component) -> dict:
    node: dict = {"type": c.type, "bom-ref": c.ref(), "name": c.name}
    if c.version:
        node["version"] = c.version
    if c.purl:
        node["purl"] = c.purl
    if c.cpe:
        node["cpe"] = c.cpe
    return node


def _vuln_node(v: Vulnerability) -> dict:
    node: dict = {"id": v.id, "source": {"name": v.source or "NVD"}, "affects": [{"ref": v.affects}]}
    if v.severity:
        node["ratings"] = [{"severity": v.severity.lower()}]
    return node


def components_from_technologies(techs: list[dict]) -> list[Component]:
    """Map recon/SCA technology dicts ({name, version, type?, purl?}) to Components."""
    out: list[Component] = []
    for t in techs or []:
        name = str(t.get("name") or "").strip()
        if not name:
            continue
        out.append(Component(
            name=name,
            version=str(t.get("version") or "").strip(),
            type=str(t.get("type") or "library"),
            purl=str(t.get("purl") or ""),
            cpe=str(t.get("cpe") or ""),
        ))
    return out


def build_sbom(
    components: list[Component],
    *,
    target: str = "",
    timestamp: str = "",
    tool_version: str = "0.0.0",
    vulnerabilities: list[Vulnerability] | None = None,
) -> dict:
    """Assemble a deterministic CycloneDX 1.5 BOM (components deduped + sorted)."""
    unique = sorted(set(components), key=lambda c: (c.name.lower(), c.version))
    bom: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"vendor": "ORTHRUS", "name": "orthrus", "version": tool_version}],
        },
        "components": [_component_node(c) for c in unique],
    }
    if target:
        bom["metadata"]["component"] = {"type": "application", "bom-ref": target, "name": target}
    vulns = [_vuln_node(v) for v in (vulnerabilities or [])]
    if vulns:
        bom["vulnerabilities"] = vulns
    return bom


def write_sbom(path: str, bom: dict) -> None:
    from pathlib import Path

    Path(path).write_text(json.dumps(bom, indent=2, sort_keys=True), encoding="utf-8")


__all__ = [
    "Component",
    "Vulnerability",
    "build_sbom",
    "components_from_technologies",
    "write_sbom",
    "SPEC_VERSION",
]
