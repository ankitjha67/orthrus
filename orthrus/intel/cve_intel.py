"""CVE threat-intelligence enrichment: CISA KEV + EPSS.

Annotates CVE findings with two high-value signals for prioritisation:

* **CISA KEV** — the vulnerability is on the Known Exploited Vulnerabilities
  catalog (actively exploited in the wild). KEV membership escalates severity to
  at least HIGH: a "medium" CVSS that is being exploited right now outranks a
  theoretical "high".
* **EPSS** — the Exploit Prediction Scoring System probability (0–1) that the CVE
  will be exploited in the next 30 days.

Data ships as an offline seed (a snapshot of well-known entries) so enrichment
works with no network; ``refresh_kev()`` re-pulls the full CISA feed (a trusted
source, not the target) when online — wired to ``orthrus update``.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

from orthrus.core.schemas import Severity

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
_KEV_FILE = os.path.join(_DATA_DIR, "cisa_kev_seed.json")
_EPSS_FILE = os.path.join(_DATA_DIR, "epss_seed.json")

CISA_KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# FIRST.org publishes the full daily EPSS dataset as a gzipped CSV (no API key).
EPSS_FEED = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def _load_json(path: str, default: object) -> object:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return default


# Loaded once at import; refresh_kev() can rewrite the seed file.
_KEV: set[str] = {c.upper() for c in _load_json(_KEV_FILE, [])}  # type: ignore[union-attr]
_EPSS: dict[str, float] = {
    k.upper(): float(v) for k, v in _load_json(_EPSS_FILE, {}).items()  # type: ignore[union-attr]
}


@dataclass(frozen=True)
class CveIntel:
    cve_id: str
    kev: bool
    epss: float | None

    @property
    def has_intel(self) -> bool:
        return self.kev or self.epss is not None


def enrich(cve_id: str) -> CveIntel:
    """Look up KEV membership and EPSS score for a CVE id (offline)."""
    cid = (cve_id or "").strip().upper()
    return CveIntel(cve_id=cid, kev=cid in _KEV, epss=_EPSS.get(cid))


def cve_ids_in(text: str) -> list[str]:
    """All CVE ids mentioned in ``text`` (e.g. a finding title), upper-cased."""
    return [m.upper() for m in _CVE_RE.findall(text or "")]


def epss_for_text(text: str) -> float | None:
    """Highest EPSS probability among any CVE ids mentioned in ``text``.

    Lets report/triage rank a finding by exploit probability without a dedicated
    schema field — the CVE id already appears in the finding's title/description.
    """
    scores = [s for cid in cve_ids_in(text) if (s := _EPSS.get(cid)) is not None]
    return max(scores) if scores else None


def escalate_severity(base: Severity, intel: CveIntel) -> Severity:
    """KEV (actively exploited) raises a sub-HIGH severity to HIGH."""
    if intel.kev and base in (Severity.MEDIUM, Severity.LOW, Severity.INFO):
        return Severity.HIGH
    return base


def summary(intel: CveIntel) -> str:
    """Short human tag, e.g. '[CISA KEV — actively exploited; EPSS 0.97]'. Empty if none."""
    parts: list[str] = []
    if intel.kev:
        parts.append("CISA KEV — actively exploited")
    if intel.epss is not None:
        parts.append(f"EPSS {intel.epss:.2f}")
    return f"[{'; '.join(parts)}]" if parts else ""


def refresh_kev(kev_json: dict) -> int:
    """Rewrite the KEV seed from a CISA feed payload. Returns the entry count."""
    cves = sorted(
        {v.get("cveID", "").upper() for v in kev_json.get("vulnerabilities", []) if v.get("cveID")}
    )
    os.makedirs(_DATA_DIR, exist_ok=True)
    with open(_KEV_FILE, "w", encoding="utf-8") as fh:
        json.dump(cves, fh, indent=0)
    _KEV.clear()
    _KEV.update(cves)
    return len(cves)


def _epss_pairs(data: object):
    """Yield (cve, score) from a {cve: score} mapping, a FIRST.org API envelope
    ({"data": [{"cve","epss"}, ...]}), or a bare list of such row dicts."""
    rows = data.get("data", data) if isinstance(data, dict) else data
    if isinstance(rows, dict):
        yield from rows.items()
    elif isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict):
                yield (row.get("cve") or row.get("cveID")), row.get("epss")


def refresh_epss(data: object) -> int:
    """Rewrite the EPSS seed from EPSS data. Accepts a {cve: score} mapping, a
    FIRST.org API envelope, or a list of row dicts. Returns the entry count."""
    mapping: dict[str, float] = {}
    for cve, score in _epss_pairs(data):
        if not cve or score is None:
            continue
        try:
            mapping[str(cve).strip().upper()] = float(score)
        except (TypeError, ValueError):
            continue
    os.makedirs(_DATA_DIR, exist_ok=True)
    with open(_EPSS_FILE, "w", encoding="utf-8") as fh:
        json.dump(mapping, fh)
    _EPSS.clear()
    _EPSS.update(mapping)
    return len(mapping)


__all__ = [
    "CveIntel",
    "enrich",
    "cve_ids_in",
    "epss_for_text",
    "escalate_severity",
    "summary",
    "refresh_kev",
    "refresh_epss",
    "CISA_KEV_FEED",
    "EPSS_FEED",
]
