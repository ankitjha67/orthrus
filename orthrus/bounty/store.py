"""Persist bug-bounty programs so ``orthrus bounty`` is program-anchored (PRD §6/§7.1).

A saved **program** records its authorization source and in/out-of-scope entries
under a name, plus the history of campaigns run against it. Re-run a program by
name without re-typing its scope, and keep an audit trail of what was scanned when.

Storage is a single JSON file (``$ORTHRUS_HOME/programs.json``, default
``~/.orthrus/programs.json``) — no database to stand up. The record round-trips
back into a :class:`ProgramScope` via the same intake parser the CLI uses, so the
authorization/kill-list checks apply identically on a resumed run.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from orthrus.bounty.scope_intake import ProgramScope, parse_program_scope


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def default_store_path() -> Path:
    home = os.environ.get("ORTHRUS_HOME")
    base = Path(home) if home else Path.home() / ".orthrus"
    return base / "programs.json"


@dataclass
class ProgramRecord:
    name: str
    authorization: str = ""              # raw --authorization source
    in_scope: list[str] = field(default_factory=list)   # raw in-scope entries
    out_scope: list[str] = field(default_factory=list)  # raw out-of-scope entries
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    last_run_at: str | None = None
    scan_ids: list[str] = field(default_factory=list)
    notes: str = ""

    def scope_text(self) -> str:
        return "\n".join([*self.in_scope, *(f"!{o}" for o in self.out_scope)])

    def to_scope(self) -> ProgramScope:
        return parse_program_scope(self.scope_text())


class ProgramStore:
    """JSON-file store of :class:`ProgramRecord` keyed by (lowercased) name."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else default_store_path()

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

    def get(self, name: str) -> ProgramRecord | None:
        row = self._read().get((name or "").lower())
        return ProgramRecord(**row) if row else None

    def list(self) -> list[ProgramRecord]:
        recs = [ProgramRecord(**r) for r in self._read().values()]
        return sorted(recs, key=lambda r: r.name.lower())

    def save(self, record: ProgramRecord) -> None:
        data = self._read()
        existing = data.get(record.name.lower())
        if existing:  # keep the original creation time across updates
            record.created_at = existing.get("created_at", record.created_at)
        record.updated_at = _now()
        data[record.name.lower()] = asdict(record)
        self._write(data)

    def delete(self, name: str) -> bool:
        data = self._read()
        if (name or "").lower() in data:
            del data[(name or "").lower()]
            self._write(data)
            return True
        return False

    def record_run(self, name: str, scan_ids: list[str]) -> None:
        rec = self.get(name)
        if rec is None:
            return
        rec.last_run_at = _now()
        rec.scan_ids = list(dict.fromkeys([*rec.scan_ids, *scan_ids]))[-50:]  # keep the last 50
        self.save(rec)


__all__ = ["ProgramRecord", "ProgramStore", "default_store_path"]
