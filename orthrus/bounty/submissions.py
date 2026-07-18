"""Track submissions and payouts across programs (PRD §7.12).

ORTHRUS never auto-files (human confirms every submission), so this is a ledger
you drive: record a report when you submit it, move it through the platform's
states (filed → triaged → accepted/duplicate → rewarded), and log the payout.
Analytics roll up total earnings and status counts so you can see per-program ROI.

Stored as a single JSON file (``$ORTHRUS_HOME/submissions.json``).
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

STATUSES = (
    "draft", "filed", "triaged", "accepted", "duplicate",
    "informative", "resolved", "rewarded", "closed", "n-a",
)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def default_submissions_path() -> Path:
    home = os.environ.get("ORTHRUS_HOME")
    base = Path(home) if home else Path.home() / ".orthrus"
    return base / "submissions.json"


@dataclass
class Submission:
    id: str = field(default_factory=lambda: secrets.token_hex(4))
    program: str = ""
    title: str = ""
    platform: str = "generic"
    severity: str = ""
    status: str = "draft"
    bounty_amount: float = 0.0
    currency: str = "USD"
    url: str = ""
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    notes: str = ""


class SubmissionStore:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else default_submissions_path()

    def _read(self) -> dict[str, dict]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError):
            return {}

    def _write(self, data: dict[str, dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)

    def add(self, sub: Submission) -> Submission:
        data = self._read()
        data[sub.id] = asdict(sub)
        self._write(data)
        return sub

    def get(self, sub_id: str) -> Submission | None:
        row = self._read().get(sub_id)
        return Submission(**row) if row else None

    def update(self, sub_id: str, **fields) -> Submission | None:
        data = self._read()
        row = data.get(sub_id)
        if row is None:
            return None
        for k, v in fields.items():
            if v is not None and k in row:
                row[k] = v
        row["updated_at"] = _now()
        data[sub_id] = row
        self._write(data)
        return Submission(**row)

    def list(self, program: str | None = None) -> list[Submission]:
        subs = [Submission(**r) for r in self._read().values()]
        if program:
            subs = [s for s in subs if s.program.lower() == program.lower()]
        return sorted(subs, key=lambda s: s.created_at, reverse=True)

    def summary(self, program: str | None = None) -> dict:
        subs = self.list(program)
        by_status: dict[str, int] = {}
        earnings: dict[str, float] = {}
        for s in subs:
            by_status[s.status] = by_status.get(s.status, 0) + 1
            if s.bounty_amount:
                earnings[s.currency] = round(earnings.get(s.currency, 0.0) + s.bounty_amount, 2)
        rewarded = sum(1 for s in subs if s.status == "rewarded")
        return {"total": len(subs), "rewarded": rewarded, "by_status": by_status, "earnings": earnings}


__all__ = ["STATUSES", "Submission", "SubmissionStore", "default_submissions_path"]
