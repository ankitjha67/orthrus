"""Promote v0.1 scan data into the v2.0 operator graph (PRD §4.2 / §22.10).

Additive and idempotent: creates (or reuses) a single "Legacy v0.1 import"
Program (self-owned-lab), then upserts every v0.1 scan's assets and findings into
the operator graph — assets by identity, findings by signature — so re-running
never duplicates. The v0.1 scan tables are never modified, so the migration is
trivially reversible (delete the legacy Program) and every v0.1 CLI path keeps
working unchanged.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from orthrus.db.store import Store
from orthrus.model.store import ProgramGraph

LEGACY_PROGRAM_NAME = "Legacy v0.1 import"


def _asset_kind(fqdn: str) -> str:
    try:
        ipaddress.ip_address(fqdn)
        return "ip"
    except ValueError:
        return "subdomain" if fqdn.count(".") >= 2 else "host"


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


async def migrate_v01(store: Store, graph: ProgramGraph, *, dry_run: bool = False) -> dict:
    """Promote all v0.1 scans/assets/findings into the operator graph.

    Returns counts. With ``dry_run`` nothing is written — it just reports what
    *would* migrate (the PRD's dry-runnable, reversible migration).
    """
    counts = {"scans": 0, "assets_seen": 0, "assets_new": 0,
              "findings_seen": 0, "findings_new": 0}

    program = await graph.get_program_by_name(LEGACY_PROGRAM_NAME)
    if program is None and not dry_run:
        program = await graph.create_program(
            LEGACY_PROGRAM_NAME, "self-owned-lab", platform="self",
            reward_range={}, tags=["legacy", "v0.1-import"],
        )
    pid = program.id if program else None

    for scan_row, _n in await store.list_scans(limit=1_000_000):
        counts["scans"] += 1
        for asset in await store.get_assets(scan_row.id):
            if not asset.fqdn:
                continue
            counts["assets_seen"] += 1
            if not dry_run:
                _asset, is_new = await graph.record_asset(
                    pid, _asset_kind(asset.fqdn), asset.fqdn.lower(), asset.fqdn,
                    discovered_by=asset.discovery_method or "v0.1-migration",
                )
                counts["assets_new"] += int(is_new)
        for _fid, finding in await store.get_findings_with_ids(scan_row.id):
            counts["findings_seen"] += 1
            if not dry_run:
                signature = f"{finding.vuln_type}|{_host(finding.url)}"
                _f, is_new = await graph.record_finding(
                    pid, finding.vuln_type, finding.title, finding.severity.value, signature,
                    confidence=finding.confidence.value,
                    found_by_tool=finding.scanner or "unknown",
                    cwe_id=finding.cwe, cvss_v3_score=finding.cvss_score,
                    cvss_v3_vector=finding.cvss_vector,
                )
                counts["findings_new"] += int(is_new)

    return {"program_id": pid, **counts}


__all__ = ["migrate_v01", "LEGACY_PROGRAM_NAME"]
