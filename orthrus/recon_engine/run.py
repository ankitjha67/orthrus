"""One recon pass for a program (PRD §7.2/§7.9) — shared by recon-run/recon-watch.

Runs every available source into the operator graph, audit-logs the pass, and —
when new assets appear — fires the configured Slack/Discord alerts. Factored out
so the one-shot command and the continuous watch loop behave identically.
"""

from __future__ import annotations

from orthrus.model.store import ProgramGraph
from orthrus.recon_engine.alerts import new_asset_message
from orthrus.recon_engine.base import ReconScope, get_recon_adapters
from orthrus.recon_engine.engine import ReconEngine, ReconResult


async def recon_once(
    graph: ProgramGraph,
    program_id: str,
    program_name: str,
    domains: list[str],
    *,
    sources: str = "all",
    notify_slack: str | None = None,
    notify_discord: str | None = None,
) -> tuple[ReconResult, dict[str, bool]]:
    adapters = get_recon_adapters(None if sources == "all" else sources.split(","))
    result = await ReconEngine(graph, adapters).run(
        program_id, ReconScope(domains=domains, program_id=program_id))
    await graph.append_audit(
        "recon-run", "completed", subject_type="program", subject_id=program_id,
        details={"new": len(result.new), "discovered": result.discovered,
                 "sources": result.sources_run},
    )

    notified: dict[str, bool] = {}
    if result.new and (notify_slack or notify_discord):
        from orthrus.integrations.notify import send_discord, send_slack
        msg = new_asset_message(program_name, result.new)
        if notify_slack:
            notified["slack"] = await send_slack(notify_slack, {"text": msg})
        if notify_discord:
            notified["discord"] = await send_discord(notify_discord, msg)
    return result, notified


__all__ = ["recon_once"]
