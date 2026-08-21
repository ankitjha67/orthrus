"""Finding deduplication + reimport-delta reconciliation.

Repeated scanning and multi-scanner coverage produce the same real issue more
than once; this collapses duplicates and turns a re-scan into a lifecycle delta
(the DefectDojo/Faraday capability, rebuilt deterministically).

* **Dedup** - a configurable per-source hash over a chosen field set collapses
  the same ``(vuln_type, path, param, location, cwe)`` reported twice (by two
  scanners or two runs) into one canonical finding, keeping the highest-
  confidence instance.
* **Reconcile** - diff a previous run against the current one into
  ``new`` / ``persistent`` / ``resolved`` (present before, gone now) /
  ``reappeared`` (came back after being marked resolved) - so persistent findings
  stay open, fixed ones auto-close, and regressions are caught.

Pure and deterministic - the same findings always hash and reconcile the same
way - so it is reproducible and unit-testable. Accepts Finding objects or dicts.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from urllib.parse import urlsplit

# Fields that identify "the same finding". ``_path`` is the URL path without the
# query so ``/x?id=1`` and ``/x?id=2`` on the same param dedupe together.
DEFAULT_HASH_FIELDS: tuple[str, ...] = (
    "vuln_type", "_path", "parameter", "param_location", "cwe",
)

_CONFIDENCE_RANK = {"tentative": 0, "firm": 1, "confirmed": 2}


def _get(finding: object, name: str) -> object:
    if isinstance(finding, dict):
        return finding.get(name)
    return getattr(finding, name, None)


def _scalar(value: object) -> str:
    return str(getattr(value, "value", value)) if value is not None else ""


def _path_of(finding: object) -> str:
    return urlsplit(_scalar(_get(finding, "url"))).path or "/"


def _confidence_rank(finding: object) -> int:
    return _CONFIDENCE_RANK.get(_scalar(_get(finding, "confidence")).lower(), 0)


def finding_hash(finding: object, fields: tuple[str, ...] = DEFAULT_HASH_FIELDS) -> str:
    """Stable 16-hex identity hash over the chosen field set."""
    parts = []
    for name in fields:
        value = _path_of(finding) if name == "_path" else _scalar(_get(finding, name))
        parts.append(f"{name}={value}")
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


@dataclass
class DedupeResult:
    unique: list
    duplicates: int
    groups: dict[str, int] = field(default_factory=dict)


def dedupe_findings(
    findings: list, fields: tuple[str, ...] = DEFAULT_HASH_FIELDS
) -> DedupeResult:
    """Collapse same-hash findings, keeping the highest-confidence instance."""
    index: dict[str, int] = {}
    unique: list = []
    groups: dict[str, int] = {}
    for f in findings:
        h = finding_hash(f, fields)
        groups[h] = groups.get(h, 0) + 1
        if h in index:
            i = index[h]
            if _confidence_rank(f) > _confidence_rank(unique[i]):
                unique[i] = f
        else:
            index[h] = len(unique)
            unique.append(f)
    duplicates = sum(c - 1 for c in groups.values())
    return DedupeResult(unique=unique, duplicates=duplicates, groups=groups)


@dataclass
class ReconcileResult:
    new: list = field(default_factory=list)
    persistent: list = field(default_factory=list)
    resolved: list = field(default_factory=list)
    reappeared: list = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "persistent": len(self.persistent),
            "resolved": len(self.resolved),
            "reappeared": len(self.reappeared),
        }


def reconcile(
    previous: list,
    current: list,
    fields: tuple[str, ...] = DEFAULT_HASH_FIELDS,
    previously_resolved: frozenset[str] = frozenset(),
) -> ReconcileResult:
    """Diff a previous run against the current one into a lifecycle delta.

    ``previously_resolved`` is the set of finding hashes an earlier run had
    already marked resolved/fixed; a current finding matching one is a
    **reappearance** (regression), reported in addition to being ``new``/
    ``persistent``.
    """
    prev_hashes = {finding_hash(f, fields) for f in previous}
    cur_by_hash: dict[str, object] = {}
    for f in current:
        cur_by_hash.setdefault(finding_hash(f, fields), f)  # first wins (already deduped ideally)

    result = ReconcileResult()
    for h, f in cur_by_hash.items():
        if h in prev_hashes:
            result.persistent.append(f)
        else:
            result.new.append(f)
        if h in previously_resolved:
            result.reappeared.append(f)
    for f in previous:
        if finding_hash(f, fields) not in cur_by_hash:
            result.resolved.append(f)
    return result


__all__ = [
    "DEFAULT_HASH_FIELDS",
    "DedupeResult",
    "ReconcileResult",
    "finding_hash",
    "dedupe_findings",
    "reconcile",
]
