"""ORTHRUS v2.0 unified domain model — the operator graph (PRD §6).

The v0.1 scan-engine persists per-scan artifacts (``orthrus.db.models``: scans →
assets/endpoints/findings, all scan-scoped). v2.0 adds the *operator graph* on top:
Program-anchored, persistent-across-scans entities that model an entire hunting
portfolio. Everything traces back to a :class:`Program` carrying a valid
authorization source — the load-bearing safety anchor (PRD §6.2, §2.3).

These tables share the v0.1 ``Base``/engine (one database, one ``store.init()``),
so the operator graph and the scan artifacts co-exist without either breaking the
other. Table names are distinct from the v0.1 scan-scoped ones.
"""

from orthrus.model import entities as _entities  # noqa: F401  (registers tables on Base)
from orthrus.model.entities import (
    PLATFORMS,
    SCOPE_ENTRY_TYPES,
    SCOPE_KINDS,
    Program,
    ScopeEntry,
    new_id,
)

__all__ = [
    "Program",
    "ScopeEntry",
    "PLATFORMS",
    "SCOPE_ENTRY_TYPES",
    "SCOPE_KINDS",
    "new_id",
]
