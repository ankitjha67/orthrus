"""Cross-run memory ledger - learn across scans, skip provably-wasteful work.

The run_manifest captures *one* scan; this remembers across scans so repeated
scanning of the same programs turns into trend data instead of duplicate work.
Two deterministic learnings, both opt-in and every skip logged:

* **Known-confirmed carry-forward** - a ``(host, path, param, vuln_class)`` that
  a previous run already *confirmed* is carried forward instead of re-tested.
* **Dead-class skip** - once a ``(tech-stack-signature, vuln_class)`` pair has
  accumulated ``>= threshold`` negatives with zero confirmations, that class is
  skipped on that stack (the learning transfers across same-stack hosts).

Pure and deterministic: timestamps / scan ids are supplied by the caller, never
read from the clock here, so the ledger is fully reproducible and unit-testable.
Disk persistence is a thin JSONL/JSON adapter kept separate from the core logic.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

DEAD_CLASS_THRESHOLD = 5  # negatives (zero confirms) on a stack -> skip that class


@dataclass(frozen=True)
class FindingRecord:
    host: str
    path: str
    param: str
    vuln_class: str
    confirmed: bool = False
    tech_sig: str = ""  # tech-stack signature the finding was observed on
    scan_id: str = ""
    timestamp: str = ""


@dataclass(frozen=True)
class SkipDecision:
    skip: bool
    reason: str  # "known-confirmed" | "dead-class" | ""


def tech_stack_signature(techs: object) -> str:
    """Deterministic key for a tech stack: sorted, lower-cased, de-duplicated."""
    if not techs:
        return ""
    items = {str(t).strip().lower() for t in techs if str(t).strip()}
    return "|".join(sorted(items))


@dataclass
class MemoryLedger:
    findings: list[FindingRecord] = field(default_factory=list)
    # (tech_sig, vuln_class) -> negative count
    negatives: dict[tuple[str, str], int] = field(default_factory=dict)

    def record_finding(self, rec: FindingRecord) -> None:
        """Record a finding, upgrading an existing entry when it becomes confirmed."""
        key = (rec.host, rec.path, rec.param, rec.vuln_class)
        for i, f in enumerate(self.findings):
            if (f.host, f.path, f.param, f.vuln_class) == key:
                if rec.confirmed and not f.confirmed:
                    self.findings[i] = rec
                return
        self.findings.append(rec)

    def record_negative(self, tech_sig: str, vuln_class: str, count: int = 1) -> None:
        k = (tech_sig, vuln_class)
        self.negatives[k] = self.negatives.get(k, 0) + count

    def confirmed_classes_for_sig(self, tech_sig: str) -> set[str]:
        return {f.vuln_class for f in self.findings if f.confirmed and f.tech_sig == tech_sig}

    def is_confirmed(self, host: str, path: str, param: str, vuln_class: str) -> bool:
        key = (host, path, param, vuln_class)
        return any(
            f.confirmed and (f.host, f.path, f.param, f.vuln_class) == key for f in self.findings
        )


def skip_decision(
    ledger: MemoryLedger,
    host: str,
    path: str,
    param: str,
    vuln_class: str,
    tech_sig: str,
    *,
    threshold: int = DEAD_CLASS_THRESHOLD,
) -> SkipDecision:
    """Should this (host, path, param, class) work-unit be skipped this run?"""
    if ledger.is_confirmed(host, path, param, vuln_class):
        return SkipDecision(True, "known-confirmed")
    neg = ledger.negatives.get((tech_sig, vuln_class), 0)
    if neg >= threshold and vuln_class not in ledger.confirmed_classes_for_sig(tech_sig):
        return SkipDecision(True, "dead-class")
    return SkipDecision(False, "")


def rollup(ledger: MemoryLedger, host: str) -> dict:
    """Per-host summary: what was tested, what was confirmed, when."""
    hf = [f for f in ledger.findings if f.host == host]
    return {
        "host": host,
        "findings": len(hf),
        "confirmed": sum(1 for f in hf if f.confirmed),
        "classes_confirmed": sorted({f.vuln_class for f in hf if f.confirmed}),
        "classes_seen": sorted({f.vuln_class for f in hf}),
        "last_scan": max((f.scan_id for f in hf if f.scan_id), default=""),
    }


# --------------------------------------------------------------- persistence
def save_ledger(ledger: MemoryLedger, directory: str | Path) -> None:
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    with (d / "findings.jsonl").open("w", encoding="utf-8") as fh:
        for f in ledger.findings:
            fh.write(json.dumps(asdict(f), sort_keys=True) + "\n")
    negs = [
        {"tech_sig": k[0], "vuln_class": k[1], "count": v}
        for k, v in sorted(ledger.negatives.items())
    ]
    with (d / "negatives.json").open("w", encoding="utf-8") as fh:
        json.dump(negs, fh, indent=2, sort_keys=True)


def load_ledger(directory: str | Path) -> MemoryLedger:
    d = Path(directory)
    ledger = MemoryLedger()
    fp = d / "findings.jsonl"
    if fp.exists():
        for line in fp.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                ledger.findings.append(FindingRecord(**json.loads(line)))
    npth = d / "negatives.json"
    if npth.exists():
        for rec in json.loads(npth.read_text(encoding="utf-8")):
            ledger.negatives[(rec["tech_sig"], rec["vuln_class"])] = rec["count"]
    return ledger


__all__ = [
    "DEAD_CLASS_THRESHOLD",
    "FindingRecord",
    "SkipDecision",
    "MemoryLedger",
    "tech_stack_signature",
    "skip_decision",
    "rollup",
    "save_ledger",
    "load_ledger",
]
