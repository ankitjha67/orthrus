"""Emergency kill switch (PRD §8.3).

``orthrus panic`` writes a flag file that the scope-enforced HTTP client checks
before *every* outbound request — when engaged, all requests are denied, turning
deny-by-default into deny-everything. It also marks in-flight scans aborted. The
state is a single file at ``$ORTHRUS_HOME/PANIC`` so it survives process death and
is trivially inspectable; ``orthrus panic --clear`` lifts it.

Deliberately simple and software-only: a firewall-level network cutoff is
OS-specific and heavier; this flag is the reliable, cross-platform core that the
one load-bearing choke point (``HttpClient._enforce_scope``) honors.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path


def panic_file() -> Path:
    home = os.environ.get("ORTHRUS_HOME")
    base = Path(home) if home else Path.home() / ".orthrus"
    return base / "PANIC"


def engage(reason: str = "") -> Path:
    """Write the panic flag; return its path."""
    path = panic_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({
            "reason": reason or "manual panic",
            "ts": datetime.now(UTC).isoformat(timespec="seconds"),
        }),
        encoding="utf-8",
    )
    return path


def is_engaged() -> bool:
    return panic_file().exists()


def details() -> dict | None:
    path = panic_file()
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"reason": "engaged", "ts": ""}


def clear() -> bool:
    """Lift the panic state; return True if one was engaged."""
    path = panic_file()
    if path.exists():
        path.unlink()
        return True
    return False


__all__ = ["panic_file", "engage", "is_engaged", "details", "clear"]
