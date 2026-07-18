"""Run a bug-bounty campaign: scan every in-scope seed, then report the bugs.

Reuses the exact core pipeline the ``scan`` command runs (recon → scan →
exploitation-confirmation) once per in-scope seed, under a shared campaign id, so
findings land in one place. Afterwards it loads them back, keeps only in-scope
findings at/above the confidence floor, deduplicates, and writes submission-ready
reports. The scope-enforced HTTP client guarantees no request ever leaves the
authorized boundary, campaign or not.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from orthrus.bounty.report import (
    CampaignReport,
    render_index,
    select_and_group,
)
from orthrus.bounty.scope_intake import ProgramScope
from orthrus.core.config import ScanConfig, ScopeConfig, get_settings
from orthrus.core.orchestrator import Orchestrator
from orthrus.db.store import Store
from orthrus.utils.logger import get_logger

logger = get_logger("bounty.campaign")

# CLI-facing type: build a per-seed ScanConfig (target, scope, unique scan id).
ConfigFactory = Callable[[str, ScopeConfig, str], ScanConfig]


@dataclass
class CampaignResult:
    report: CampaignReport
    seeds: list[str] = field(default_factory=list)
    scan_ids: list[str] = field(default_factory=list)
    failed_seeds: list[str] = field(default_factory=list)


async def run_campaign(
    program: ProgramScope,
    make_config: ConfigFactory,
    *,
    campaign_id: str,
    min_confidence: str = "firm",
    suppressions: list[dict] | None = None,
) -> CampaignResult:
    """Scan each in-scope seed with the full pipeline, then dedupe + filter the bugs."""
    settings = get_settings()
    seeds = program.in_scope_seeds()
    result = CampaignResult(report=CampaignReport(), seeds=seeds)

    for i, seed in enumerate(seeds, 1):
        scope = program.scope_config()
        # Authorize the seed's explicit port so custom-port assets aren't blocked
        # by the scope-enforced client (mirrors the scan command's build_scope).
        port = urlsplit(seed).port
        if port and scope.ports and port not in scope.ports:
            scope.ports.append(port)
        cfg = make_config(seed, scope, f"{campaign_id}-{i:02d}")
        orch = Orchestrator(cfg, settings)
        status = "failed"
        try:
            await orch.setup()
            await orch.run_recon()
            await orch.run_scan()
            if not cfg.no_exploit:
                await orch.run_exploit()
            status = "completed"
            result.scan_ids.append(orch.scan_id)
            logger.info("bounty: finished %s (scan %s)", seed, orch.scan_id)
        except Exception:
            logger.exception("bounty: scan failed for %s", seed)
            result.failed_seeds.append(seed)
        finally:
            await orch.teardown(status)

    # Aggregate findings across every campaign scan, carrying confirmation techniques.
    store = Store(settings.db_url, encryption_key=settings.encryption_key)
    findings = []
    techniques: dict[str, str] = {}
    for sid in result.scan_ids:
        for db_id, finding in await store.get_findings_with_ids(sid):
            findings.append(finding)
            for ex in await store.get_exploitations(db_id):
                if ex.success:
                    techniques[finding.id] = ex.technique
                    break

    result.report = select_and_group(
        findings, program, min_confidence=min_confidence, techniques=techniques,
        suppressions=suppressions,
    )
    return result


def _slug(text: str, cap: int = 40) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return (s[:cap].rstrip("-")) or "bug"


def write_reports(report: CampaignReport, outdir: str | Path, *, program_name: str = "",
                  platform: str = "generic") -> list[str]:
    """Write the index + one Markdown file per bug; return the filenames written.

    ``platform`` selects the report shape (generic, or hackerone/bugcrowd/intigriti/
    yeswehack/immunefi) so each bug pastes straight into that program's form.
    """
    from orthrus.bounty import platforms

    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "README.md").write_text(render_index(report, program_name), encoding="utf-8")
    written = ["README.md"]
    for i, group in enumerate(report.groups, 1):
        sev = group.lead.severity.value if hasattr(group.lead.severity, "value") else group.lead.severity
        name = f"bug-{i:02d}-{sev}-{_slug(group.lead.title)}.md"
        content = platforms.render(group, platform=platform, program_name=program_name)
        (out / name).write_text(content, encoding="utf-8")
        written.append(name)
    return written


__all__ = ["CampaignResult", "run_campaign", "write_reports"]
