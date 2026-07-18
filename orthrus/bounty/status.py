"""One-view operator status — the cockpit, in the terminal.

Aggregates the bounty module's persistent stores (programs, submissions, history,
audit) into a single snapshot: what you're hunting, what you've earned, how many
bugs you've catalogued, and whether the audit trail is intact.
"""

from __future__ import annotations

from orthrus.bounty.audit import AuditLog
from orthrus.bounty.history import HistoryStore
from orthrus.bounty.store import ProgramStore
from orthrus.bounty.submissions import SubmissionStore


def gather_status() -> dict:
    programs = ProgramStore().list()
    audit = AuditLog()
    ok, bad = audit.verify()
    return {
        "programs": [
            {"name": p.name, "in_scope": len(p.in_scope), "out_scope": len(p.out_scope),
             "authorization": p.authorization, "last_run": p.last_run_at, "campaigns": len(p.scan_ids)}
            for p in programs
        ],
        "submissions": SubmissionStore().summary(),
        "history_signatures": HistoryStore().count(),
        "audit": {"entries": len(audit.entries()), "intact": ok, "first_bad": bad},
    }


__all__ = ["gather_status"]
