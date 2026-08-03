"""Per-scan reproducibility manifest (Glasswing lesson 4.5: audit-traceable determinism).

A compact, hashable record of exactly what a scan *was* and what it *found*, so a run
is auditable and reproducible months later - and two scans of the same scope can be
diffed (the basis for honest MTTA). The whitepaper's requirement is that the same
evidence always produces the same decision; the ``manifest_hash`` makes that checkable:
it fingerprints the run's inputs and finding-set while deliberately **excluding**
timestamps and wall-clock duration (which vary), so a re-run over the same target,
scope, config and findings reproduces the identical hash.

Pure and dependency-free; the network/orchestrator side just supplies the values.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from urllib.parse import urlsplit


def canonical_json(obj: object) -> str:
    """Deterministic JSON: sorted keys, no incidental whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_of(obj: object) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def _sev(finding: object) -> str:
    value = getattr(finding, "severity", "info")
    return getattr(value, "value", str(value)).lower()


def finding_signature(finding: object) -> str:
    """A stable, evidence-free identity for a finding (order-independent, no nonces)."""
    parts = urlsplit(getattr(finding, "url", "") or "")
    vt = (getattr(finding, "vuln_type", "") or "").lower()
    param = getattr(finding, "parameter", "") or ""
    cwe = getattr(finding, "cwe", "") or ""
    return f"{vt}|{parts.netloc}|{parts.path or '/'}|{param}|{cwe}"


def finding_digest(findings: list) -> dict:
    """Counts by severity + a hash of the sorted finding signatures."""
    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[_sev(f)] = by_severity.get(_sev(f), 0) + 1
    sigs = sorted(finding_signature(f) for f in findings)
    return {
        "count": len(findings),
        "by_severity": dict(sorted(by_severity.items())),
        "signature_hash": sha256_of(sigs),
    }


def _duration(started_at: str, finished_at: str) -> float | None:
    try:
        delta = datetime.fromisoformat(finished_at) - datetime.fromisoformat(started_at)
        return round(delta.total_seconds(), 3)
    except (ValueError, TypeError):
        return None


@dataclass(frozen=True)
class ScanManifest:
    tool_version: str
    target: str
    scope_hash: str
    config_hash: str
    modules: list[str]
    findings: dict
    manifest_hash: str
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float | None = None

    def as_dict(self) -> dict:
        return asdict(self)


def build_manifest(
    *,
    tool_version: str,
    target: str,
    scope_rules: list,
    config: dict,
    modules: list,
    findings: list,
    started_at: str = "",
    finished_at: str = "",
) -> ScanManifest:
    """Assemble a deterministic scan manifest.

    ``manifest_hash`` covers version, target, scope, config, modules and the finding
    digest - everything that should reproduce - and excludes the timestamps, so it is a
    true "same evidence -> same fingerprint" value.
    """
    scope_hash = sha256_of(sorted(str(r) for r in scope_rules))
    config_hash = sha256_of(config if isinstance(config, dict) else {})
    mods = sorted(str(m) for m in modules)
    digest = finding_digest(findings)
    manifest_hash = sha256_of({
        "tool_version": tool_version,
        "target": target,
        "scope_hash": scope_hash,
        "config_hash": config_hash,
        "modules": mods,
        "findings": digest,
    })
    return ScanManifest(
        tool_version=tool_version,
        target=target,
        scope_hash=scope_hash,
        config_hash=config_hash,
        modules=mods,
        findings=digest,
        manifest_hash=manifest_hash,
        started_at=started_at,
        finished_at=finished_at,
        duration_seconds=_duration(started_at, finished_at),
    )


def write_manifest(path: str, manifest: ScanManifest) -> None:
    from pathlib import Path

    Path(path).write_text(
        json.dumps(manifest.as_dict(), indent=2, sort_keys=True), encoding="utf-8"
    )


__all__ = [
    "ScanManifest",
    "build_manifest",
    "write_manifest",
    "finding_digest",
    "finding_signature",
    "canonical_json",
    "sha256_of",
]
