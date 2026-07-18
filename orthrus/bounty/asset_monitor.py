"""Cross-run asset monitoring — catch NEW in-scope surface (PRD §7.9).

A bug-bounty program's scope is not static: teams ship new subdomains, spin up
staging, expose new APIs. The single highest-signal event in bounty hunting is a
*fresh, untested asset appearing in an existing program's scope* — surface that
nobody has looked at yet. This keeps a per-program snapshot of the live in-scope
hosts and, on the next enumeration, tells you exactly which ones are new (and
which stopped resolving), so you can go straight at the fresh surface.

Pure and deterministic given the host set: ``record`` diffs the incoming assets
against the program's last snapshot, persists the new snapshot, and returns the
diff. Stored as one JSON file, ``$ORTHRUS_HOME/asset_snapshots.json``, keyed by
(lowercased) program name.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def default_snapshot_path() -> Path:
    home = os.environ.get("ORTHRUS_HOME")
    base = Path(home) if home else Path.home() / ".orthrus"
    return base / "asset_snapshots.json"


def _norm(hosts) -> list[str]:
    """Lowercase, strip, dedupe, drop blanks — a stable host set."""
    seen = {(h or "").strip().lower().rstrip(".") for h in hosts}
    seen.discard("")
    return sorted(seen)


@dataclass
class AssetDiff:
    program: str
    added: list[str] = field(default_factory=list)     # in scope now, weren't last run
    removed: list[str] = field(default_factory=list)    # were last run, gone now
    total: int = 0                                       # size of the current snapshot
    is_first: bool = False                               # no prior snapshot existed

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed)

    def summary(self) -> str:
        if self.is_first:
            return f"baseline recorded — {self.total} in-scope asset(s)"
        if not self.has_changes:
            return f"no change — {self.total} in-scope asset(s)"
        return f"+{len(self.added)} new / -{len(self.removed)} gone ({self.total} total)"

    def to_dict(self) -> dict:
        return {"program": self.program, "added": self.added, "removed": self.removed,
                "total": self.total, "is_first": self.is_first, "summary": self.summary()}


class AssetMonitor:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else default_snapshot_path()

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

    def latest(self, program: str) -> list[str]:
        return list(self._read().get((program or "").lower(), {}).get("assets", []))

    def record(self, program: str, assets) -> AssetDiff:
        """Snapshot ``assets`` for ``program`` and return the diff vs the prior snapshot."""
        key = (program or "").lower()
        data = self._read()
        prior_entry = data.get(key)
        current = _norm(assets)

        if prior_entry is None:
            diff = AssetDiff(program, added=current, removed=[], total=len(current), is_first=True)
        else:
            prior = set(prior_entry.get("assets", []))
            cur = set(current)
            diff = AssetDiff(
                program,
                added=sorted(cur - prior),
                removed=sorted(prior - cur),
                total=len(current),
            )
        data[key] = {"program": program, "assets": current, "updated_at": _now(),
                     "runs": int((prior_entry or {}).get("runs", 0)) + 1}
        self._write(data)
        return diff


__all__ = ["AssetMonitor", "AssetDiff", "default_snapshot_path"]
