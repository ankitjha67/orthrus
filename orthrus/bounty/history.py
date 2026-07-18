"""Recall bugs you've seen in earlier campaigns (PRD §7.5).

Keeps a small archive of every reportable bug's *signature*
(``vuln_type|normalized-title|host``) across runs, so a new campaign can tell you
"you've reported this exact bug before" — the difference between a fresh finding
and re-submitting a known/duplicate issue. Cross-program, so re-finding the same
bug on the same asset under a different engagement still surfaces.

Stored as JSON at ``$ORTHRUS_HOME/history.json``.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from orthrus.bounty.report import _host, _norm_title


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def default_history_path() -> Path:
    home = os.environ.get("ORTHRUS_HOME")
    base = Path(home) if home else Path.home() / ".orthrus"
    return base / "history.json"


def signature(finding) -> str:
    return f"{(finding.vuln_type or '').lower()}|{_norm_title(finding.title)}|{_host(finding.url)}"


class HistoryStore:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else default_history_path()

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

    def seen_before(self, finding) -> dict | None:
        return self._read().get(signature(finding))

    def record(self, findings: list, program: str = "") -> int:
        """Archive each finding's signature; return how many were **already known**
        before this call (i.e. previously reported)."""
        data = self._read()
        prior = 0
        for f in findings:
            sig = signature(f)
            entry = data.get(sig)
            if entry:
                prior += 1
                entry["last_seen"] = _now()
                entry["count"] = int(entry.get("count", 1)) + 1
                if program and program not in entry.get("programs", []):
                    entry.setdefault("programs", []).append(program)
            else:
                data[sig] = {"first_seen": _now(), "last_seen": _now(), "count": 1,
                             "programs": [program] if program else []}
        self._write(data)
        return prior


__all__ = ["HistoryStore", "signature", "default_history_path"]
