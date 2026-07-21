"""One-view operator status - the cockpit, in the terminal.

Aggregates the bounty module's persistent stores (programs, submissions, history,
audit, mute rules, tracked assets, LLM spend) into a single snapshot: what you're
hunting, what you've earned, how many bugs you've catalogued, and whether the
audit trail is intact.
"""

from __future__ import annotations

from orthrus.bounty.asset_monitor import AssetMonitor
from orthrus.bounty.audit import AuditLog
from orthrus.bounty.cost import CostLedger
from orthrus.bounty.history import HistoryStore
from orthrus.bounty.store import ProgramStore
from orthrus.bounty.submissions import SubmissionStore
from orthrus.bounty.suppress import SuppressionStore


def gather_status() -> dict:
    programs = ProgramStore().list()
    audit = AuditLog()
    ok, bad = audit.verify()

    supp = SuppressionStore()
    assets = AssetMonitor()
    total_mutes = sum(len(supp.rules(p.name)) for p in programs)
    total_assets = sum(len(assets.latest(p.name)) for p in programs)
    cost = CostLedger().summary()

    return {
        "programs": [
            {"name": p.name, "in_scope": len(p.in_scope), "out_scope": len(p.out_scope),
             "authorization": p.authorization, "last_run": p.last_run_at, "campaigns": len(p.scan_ids),
             "max_rps": p.max_rps, "identify": p.identify,
             "mute_rules": len(supp.rules(p.name)), "assets": len(assets.latest(p.name))}
            for p in programs
        ],
        "submissions": SubmissionStore().summary(),
        "history_signatures": HistoryStore().count(),
        "audit": {"entries": len(audit.entries()), "intact": ok, "first_bad": bad},
        "mute_rules": total_mutes,
        "tracked_assets": total_assets,
        "cost": {"total_usd": cost["total_usd"], "entries": cost["entries"]},
    }


__all__ = ["gather_status"]
