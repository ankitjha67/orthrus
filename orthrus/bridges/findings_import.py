"""Import findings from external tools into the operator graph (PRD §7.12).

Where ``import-traffic`` folds the request *surface* into the graph, this folds the
*findings* a tool (or you) already flagged - Caido Findings, Burp scanner issues,
SARIF (semgrep/codeql/...), an ORTHRUS ``findings.json``, or a generic JSON list -
so they land in the same deduped, priority-ranked ProgramFinding queue as scans.

Every parser is pure and tolerant (returns ``[]`` on garbage); the Burp/XML path is
XXE-guarded like the traffic bridge. Deny-by-default still applies: an optional
scope predicate drops findings whose host is out of scope.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from orthrus.bounty.report import _host, _norm_title
from orthrus.bridges.burp import _XXE_TOKENS, UnsafeXmlError

if TYPE_CHECKING:
    from orthrus.model.store import ProgramGraph

_SEV = {
    "critical": "critical", "high": "high", "medium": "medium", "low": "low",
    "info": "info", "informational": "info", "information": "info",
    "error": "high", "warning": "medium", "note": "low", "none": "info",
}
# tool confidence -> operator-graph FINDING_CONFIDENCES
_CONF = {
    "certain": "confirmed", "confirmed": "confirmed", "firm": "firm",
    "tentative": "tentative", "high": "firm", "medium": "firm", "low": "tentative",
}


def _sev(value: str | None, default: str = "info") -> str:
    return _SEV.get(str(value or "").strip().lower(), default)


def _conf(value: str | None, default: str = "firm") -> str:
    return _CONF.get(str(value or "").strip().lower(), default)


def _cwe(text: str | None) -> str | None:
    m = re.search(r"CWE-\d+", str(text or ""), re.IGNORECASE)
    return m.group(0).upper() if m else None


@dataclass
class ImportedFinding:
    """A tool-neutral finding ready to fold into the operator graph."""

    vuln_class: str = "imported"
    title: str = "(untitled)"
    severity: str = "info"
    confidence: str = "firm"
    location: str = ""          # a URL or file:line
    description: str = ""
    cwe: str | None = None
    tool: str = "import"

    def signature(self) -> str:
        return f"{(self.vuln_class or '').lower()}|{_host(self.location)}|{_norm_title(self.title)}"


def _classify(title: str) -> str:
    """Best-effort vuln_class from a finding title (keeps dedup stable)."""
    low = (title or "").lower()
    for kw, cls in (("sql", "sqli"), ("xss", "xss"), ("cross-site request", "csrf"),
                    ("cross-site scripting", "xss"), ("scripting", "xss"), ("csrf", "csrf"),
                    ("open redirect", "open-redirect"), ("ssrf", "ssrf"), ("idor", "idor"),
                    ("access control", "broken-authorization"), ("authentication", "auth"),
                    ("information disclosure", "info-disclosure"),
                    ("privilege", "privilege-escalation"), ("traversal", "lfi"),
                    ("injection", "injection"), ("redirect", "open-redirect")):
        if kw in low:
            return cls
    return "imported"


# --------------------------------------------------------------- format parsers
def parse_sarif(text: str) -> list[ImportedFinding]:
    """SARIF 2.1.0 (semgrep / codeql / many SAST tools)."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out: list[ImportedFinding] = []
    for run in (data.get("runs") or []) if isinstance(data, dict) else []:
        tool = (((run.get("tool") or {}).get("driver") or {}).get("name")) or "sarif"
        for res in run.get("results") or []:
            if not isinstance(res, dict):
                continue
            msg = ((res.get("message") or {}).get("text")) or res.get("ruleId") or "finding"
            loc = ""
            locs = res.get("locations") or []
            if locs and isinstance(locs[0], dict):
                phys = (locs[0].get("physicalLocation") or {})
                uri = ((phys.get("artifactLocation") or {}).get("uri")) or ""
                line = (phys.get("region") or {}).get("startLine")
                loc = f"{uri}:{line}" if uri and line else uri
            title = str(res.get("ruleId") or msg)[:140]
            out.append(ImportedFinding(
                vuln_class=_classify(title + " " + str(msg)),
                title=title, severity=_sev(res.get("level"), "medium"),
                confidence="firm", location=loc, description=str(msg)[:800],
                cwe=_cwe(json.dumps(res.get("properties") or {})), tool=str(tool)))
    return out


def parse_burp_issues(text: str) -> list[ImportedFinding]:
    """Burp Suite scanner issues XML export (<issues><issue>...)."""
    import xml.etree.ElementTree as ET
    raw = (text or "").encode("utf-8", "replace")
    if _XXE_TOKENS.search(raw):
        raise UnsafeXmlError("refusing Burp issues XML that declares entities/external refs (XXE).")
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []

    def _t(el, tag):
        node = el.find(tag)
        return (node.text or "").strip() if node is not None and node.text else ""

    out: list[ImportedFinding] = []
    for issue in root.iter("issue"):
        name = _t(issue, "name") or "Burp issue"
        host = _t(issue, "host")
        path = _t(issue, "path")
        out.append(ImportedFinding(
            vuln_class=_classify(name), title=name[:140],
            severity=_sev(_t(issue, "severity"), "info"),
            confidence=_conf(_t(issue, "confidence")),
            location=f"{host}{path}" if host else path,
            description=re.sub("<[^>]+>", " ", _t(issue, "issueBackground"))[:800],
            cwe=_cwe(_t(issue, "vulnerabilityClassifications")), tool="burp"))
    return out


def _unwrap_json_list(data) -> list[dict]:
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        for key in ("findings", "results", "issues", "vulnerabilities", "data"):
            v = data.get(key)
            if isinstance(v, dict) and isinstance(v.get("edges"), list):
                return [e["node"] for e in v["edges"] if isinstance(e, dict) and isinstance(e.get("node"), dict)]
            if isinstance(v, list):
                return [d for d in v if isinstance(d, dict)]
    return []


def _first(d: dict, *keys, default=None):
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


def parse_caido_findings(text: str) -> list[ImportedFinding]:
    """Caido Findings JSON export (tolerant of envelope + field-name variants)."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out: list[ImportedFinding] = []
    for d in _unwrap_json_list(data):
        title = str(_first(d, "title", "name", "description", default="Caido finding"))[:140]
        url = str(_first(d, "url", "host", "location", default=""))
        req = d.get("request") if isinstance(d.get("request"), dict) else {}
        if not url and req:
            host = _first(req, "host", "hostname", default="")
            path = _first(req, "path", default="")
            url = f"https://{host}{path}" if host else ""
        out.append(ImportedFinding(
            vuln_class=_classify(title), title=title,
            severity=_sev(_first(d, "severity", "risk"), "info"),
            confidence=_conf(_first(d, "confidence")),
            location=url, description=str(_first(d, "description", "notes", default=""))[:800],
            cwe=_cwe(json.dumps(d)), tool="caido"))
    return out


def parse_orthrus_findings(text: str) -> list[ImportedFinding]:
    """An ORTHRUS report findings.json (round-trip its own export)."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    items = data.get("findings") if isinstance(data, dict) else data
    out: list[ImportedFinding] = []
    for d in items if isinstance(items, list) else []:
        if not isinstance(d, dict):
            continue
        out.append(ImportedFinding(
            vuln_class=str(_first(d, "vuln_type", "vuln_class", default="imported")),
            title=str(_first(d, "title", default="(untitled)"))[:140],
            severity=_sev(d.get("severity")), confidence=_conf(d.get("confidence"), "firm"),
            location=str(_first(d, "url", "location", default="")),
            description=str(d.get("description") or "")[:800],
            cwe=_cwe(str(d.get("cwe") or "")), tool=str(d.get("scanner") or "orthrus")))
    return out


def parse_generic_json(text: str) -> list[ImportedFinding]:
    """A best-effort generic JSON list of finding-ish dicts."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out: list[ImportedFinding] = []
    for d in _unwrap_json_list(data):
        title = str(_first(d, "title", "name", "message", "summary", "rule", default="finding"))[:140]
        out.append(ImportedFinding(
            vuln_class=_classify(title), title=title,
            severity=_sev(_first(d, "severity", "level", "risk")),
            confidence=_conf(_first(d, "confidence")),
            location=str(_first(d, "url", "location", "path", "target", default="")),
            description=str(_first(d, "description", "detail", "message", default=""))[:800],
            cwe=_cwe(json.dumps(d)), tool="generic"))
    return out


PARSERS: dict[str, Callable[[str], list[ImportedFinding]]] = {
    "sarif": parse_sarif,
    "burp": parse_burp_issues,
    "caido": parse_caido_findings,
    "orthrus": parse_orthrus_findings,
    "generic": parse_generic_json,
    "csv": lambda t: parse_generic_json(json.dumps(list(csv.DictReader(io.StringIO(t))))),
}


def detect_findings_format(text: str, path: str) -> str:
    low = path.lower()
    if low.endswith(".sarif"):
        return "sarif"
    if low.endswith(".csv"):
        return "csv"
    stripped = (text or "").lstrip()
    if stripped.startswith("<"):
        return "burp"
    if '"$schema"' in stripped[:400] and "sarif" in stripped[:400].lower():
        return "sarif"
    if '"runs"' in stripped[:400] and '"results"' in stripped[:600]:
        return "sarif"
    if '"vuln_type"' in stripped[:2000] or '"scanner"' in stripped[:2000]:
        return "orthrus"
    return "caido" if stripped.startswith(("[", "{")) else "generic"


@dataclass
class FindingsImportResult:
    source: str = "import"
    total: int = 0
    new: int = 0
    seen: int = 0
    skipped_out_of_scope: int = 0


async def fold_findings(
    graph: ProgramGraph, program_id: str, findings: list[ImportedFinding],
    *, source: str = "import", in_scope: Callable[[str], bool] | None = None,
) -> FindingsImportResult:
    """Record imported findings into the operator graph (deduped by signature)."""
    from orthrus.bounty.triage import priority_score

    res = FindingsImportResult(source=source, total=len(findings))
    for f in findings:
        host = _host(f.location)
        if in_scope is not None and host and not in_scope(host):
            res.skipped_out_of_scope += 1
            continue
        try:
            score = priority_score(type("F", (), {
                "severity": f.severity, "confidence": f.confidence, "vuln_type": f.vuln_class,
                "cwe": f.cwe, "url": f.location, "cvss_score": None})())
        except Exception:  # noqa: BLE001 - scoring is best-effort
            score = None
        _finding, is_new = await graph.record_finding(
            program_id, f.vuln_class, f.title, f.severity, f.signature(),
            confidence=f.confidence, found_by_tool=f.tool, cwe_id=f.cwe,
            priority_score=score)
        if is_new:
            res.new += 1
        else:
            res.seen += 1
    return res


__all__ = [
    "ImportedFinding", "FindingsImportResult", "PARSERS", "detect_findings_format",
    "fold_findings", "parse_sarif", "parse_burp_issues", "parse_caido_findings",
    "parse_orthrus_findings", "parse_generic_json",
]
