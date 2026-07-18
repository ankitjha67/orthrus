"""Per-program mute rules — suppress known-noise findings (PRD §7.5 triage).

Every real bounty program accumulates *known noise*: an informational header
finding on a marketing host the program explicitly considers out-of-policy, a
class the team has said they won't pay for. Re-surfacing it every run is friction.
A mute rule says "for this program, don't report findings matching X" — matched
by vuln_type, host (exact or subdomain), and/or a title substring. The campaign
report counts what it suppressed (honest — nothing silently vanishes) but keeps
it out of the submission queue.

Safety: a rule with no criteria matches **nothing** — you can never accidentally
mute an entire program. Stored as JSON at ``$ORTHRUS_HOME/suppressions.json``,
keyed by (lowercased) program name.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from orthrus.bounty.report import _host


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def default_suppress_path() -> Path:
    home = os.environ.get("ORTHRUS_HOME")
    base = Path(home) if home else Path.home() / ".orthrus"
    return base / "suppressions.json"


def make_rule(*, vuln_type: str = "", host: str = "", title_contains: str = "",
              reason: str = "") -> dict:
    """Build a normalized rule dict. Raises if no criteria are given (never mute all)."""
    rule = {
        "vuln_type": (vuln_type or "").strip().lower(),
        "host": (host or "").strip().lower().rstrip("."),
        "title_contains": (title_contains or "").strip(),
        "reason": (reason or "").strip(),
        "added": _now(),
    }
    if not (rule["vuln_type"] or rule["host"] or rule["title_contains"]):
        raise ValueError("a mute rule needs at least one of vuln_type / host / title_contains")
    return rule


def rule_matches(rule: dict, finding) -> bool:
    """True if ``finding`` matches every criterion set on ``rule`` (empty rule → False)."""
    vt = (rule.get("vuln_type") or "").lower()
    host = (rule.get("host") or "").lower()
    tc = (rule.get("title_contains") or "").lower()
    if not (vt or host or tc):
        return False  # never match on an empty rule
    if vt and (getattr(finding, "vuln_type", "") or "").lower() != vt:
        return False
    if host:
        fh = _host(getattr(finding, "url", ""))
        if fh != host and not fh.endswith("." + host):
            return False
    if tc and tc not in (getattr(finding, "title", "") or "").lower():
        return False
    return True


def matching_rule(rules, finding) -> dict | None:
    for r in rules or []:
        if rule_matches(r, finding):
            return r
    return None


class SuppressionStore:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else default_suppress_path()

    def _read(self) -> dict[str, list]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError):
            return {}

    def _write(self, data: dict[str, list]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)

    def rules(self, program: str) -> list[dict]:
        return list(self._read().get((program or "").lower(), []))

    def add(self, program: str, rule: dict) -> None:
        data = self._read()
        data.setdefault((program or "").lower(), []).append(rule)
        self._write(data)

    def remove(self, program: str, index: int) -> bool:
        data = self._read()
        rules = data.get((program or "").lower(), [])
        if 0 <= index < len(rules):
            del rules[index]
            self._write(data)
            return True
        return False


__all__ = ["SuppressionStore", "make_rule", "rule_matches", "matching_rule",
           "default_suppress_path"]
