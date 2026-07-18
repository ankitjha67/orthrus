"""Tamper-evident engagement audit log (PRD §6 / §8.5 / §11).

An append-only, hash-chained record of the security-relevant things a bounty run
does: which program was authorized, what was refused by the kill-list, and what
each campaign scanned. Each entry stores the SHA-256 of the previous entry plus
its own hash over its contents, so any edit or deletion breaks the chain and
``verify()`` reports exactly where.

Stored as JSON Lines at ``$ORTHRUS_HOME/audit.log.jsonl`` (default
``~/.orthrus/audit.log.jsonl``) — no database, and cheap to append.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

_GENESIS = "genesis"


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def default_audit_path() -> Path:
    home = os.environ.get("ORTHRUS_HOME")
    base = Path(home) if home else Path.home() / ".orthrus"
    return base / "audit.log.jsonl"


def _hash(body: dict) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else default_audit_path()

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    out.append({"_corrupt": line})
        return out

    def _last_hash(self) -> str:
        rows = self.entries()
        return rows[-1].get("row_hash", _GENESIS) if rows else _GENESIS

    def append(self, event: str, action: str, details: dict | None = None) -> dict:
        body = {
            "ts": _now(), "event": event, "action": action,
            "details": details or {}, "prev_hash": self._last_hash(),
        }
        entry = {**body, "row_hash": _hash(body)}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def verify(self) -> tuple[bool, int]:
        """Return ``(ok, first_bad_index)``; ``first_bad_index`` is -1 when intact."""
        prev = _GENESIS
        for i, e in enumerate(self.entries()):
            if "_corrupt" in e:
                return False, i
            body = {k: v for k, v in e.items() if k != "row_hash"}
            if body.get("prev_hash") != prev or _hash(body) != e.get("row_hash"):
                return False, i
            prev = e["row_hash"]
        return True, -1


__all__ = ["AuditLog", "default_audit_path"]
