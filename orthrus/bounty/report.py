"""Turn confirmed findings into submission-ready bug-bounty reports.

One Markdown file per (deduplicated) bug, written the way a triager wants to read
it: a clear title, severity + CVSS, the affected asset, copy-paste **steps to
reproduce**, impact, and remediation. Plus an index over the whole campaign.

Two filters keep the output signal-dense - exactly what stops a program from
muting you:

* **In scope only** - a finding whose host isn't in the program scope (or is
  under an exclusion) is dropped.
* **Confidence floor** - defaults to ``firm`` (confirmed + firm), so unproven
  ``tentative`` heuristics don't reach a human triager unless asked for.

Nothing here calls a model; it's deterministic and fast. (`orthrus ai-report`
remains available for a narrative write-up.)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from orthrus.bounty.ontology import is_destructive
from orthrus.bounty.triage import priority_score
from orthrus.core.schemas import Finding
from orthrus.reporting.reproduce import build_snippets

_CONF_RANK = {"tentative": 0, "firm": 1, "confirmed": 2}
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_BOUNTY_HINT = {
    "critical": "typically the program's top reward band",
    "high": "usually a high reward",
    "medium": "a moderate reward",
    "low": "a small reward, if any",
    "info": "usually informational - often not rewarded",
}
_TITLE_TAIL = re.compile(r"\s+(?:via|in|on|through|at)\s+", re.IGNORECASE)


def _conf(value: object) -> str:
    return getattr(value, "value", str(value)).lower()


def _sev(value: object) -> str:
    return getattr(value, "value", str(value)).lower()


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _norm_title(title: str) -> str:
    base = _TITLE_TAIL.split(title or "", maxsplit=1)[0]
    base = re.sub(r"\s*\([^)]*\)\s*$", "", base)
    return base.strip() or (title or "").strip()


def _slug(text: str, cap: int = 48) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return (s[:cap].rstrip("-")) or "finding"


@dataclass
class BugGroup:
    """A deduplicated bug: the worst instance plus every affected location."""

    lead: Finding
    instances: list[Finding] = field(default_factory=list)
    technique: str | None = None  # how it was confirmed, if it was


@dataclass
class CampaignReport:
    groups: list[BugGroup] = field(default_factory=list)
    considered: int = 0
    out_of_scope: int = 0
    below_confidence: int = 0
    suppressed: int = 0

    @property
    def reportable(self) -> int:
        return len(self.groups)


def select_and_group(
    findings: list[Finding],
    program,
    *,
    min_confidence: str = "firm",
    techniques: dict[str, str] | None = None,
    suppressions: list[dict] | None = None,
) -> CampaignReport:
    """Filter to in-scope findings at/above the confidence floor, then dedupe.

    ``suppressions`` are per-program mute rules; a matching finding is counted
    (``report.suppressed``) but kept out of the reportable queue.
    """
    from orthrus.bounty.suppress import matching_rule

    floor = _CONF_RANK.get(min_confidence.lower(), 1)
    techniques = techniques or {}
    report = CampaignReport(considered=len(findings))
    groups: dict[tuple, BugGroup] = {}
    order: list[tuple] = []
    for f in findings:
        host = _host(f.url)
        if not program.is_in_scope(host):
            report.out_of_scope += 1
            continue
        if suppressions and matching_rule(suppressions, f) is not None:
            report.suppressed += 1
            continue
        if _CONF_RANK.get(_conf(f.confidence), 0) < floor:
            report.below_confidence += 1
            continue
        key = (f.vuln_type, _norm_title(f.title), host)
        if key not in groups:
            groups[key] = BugGroup(lead=f, instances=[f], technique=techniques.get(f.id))
            order.append(key)
        else:
            g = groups[key]
            g.instances.append(f)
            if (_SEV_RANK.get(_sev(f.severity), 0), f.cvss_score or 0) > (
                _SEV_RANK.get(_sev(g.lead.severity), 0), g.lead.cvss_score or 0
            ):
                g.lead = f
            g.technique = g.technique or techniques.get(f.id)
    report.groups = [groups[k] for k in order]
    # Rank as a work queue by composite priority (a confirmed medium can outrank a
    # tentative high), tie-broken by severity then CVSS.
    report.groups.sort(key=lambda g: (-priority_score(g.lead),
                                      -_SEV_RANK.get(_sev(g.lead.severity), 0),
                                      -(g.lead.cvss_score or 0)))
    return report


def render_submission(group: BugGroup, program_name: str = "", *, prior_seen: int = 0) -> str:
    """One triager-ready Markdown report for a single bug group.

    ``prior_seen`` > 0 adds a duplicate-warning callout: this bug matched a
    finding from that many earlier runs, so it may already be reported.
    """
    f = group.lead
    sev = _sev(f.severity)
    cvss = f"{f.cvss_score} ({f.cvss_vector})" if f.cvss_score is not None else "not scored"
    conf = _conf(f.confidence)
    proof = f" - re-proven by `{group.technique}`" if (conf == "confirmed" and group.technique) else ""
    ev = f.evidence
    snippets = build_snippets(url=f.url, request_raw=getattr(ev, "request_raw", None))

    parts = [
        f"# [{sev.upper()}] {_norm_title(f.title)}",
        "",
        (f"**Program:** {program_name}  " if program_name else "") + f"\n**Asset:** {f.url}",
        f"**Severity:** {sev.capitalize()} - CVSS {cvss}",
        f"**Weakness:** {f.cwe or 'n/a'}",
        f"**Confidence:** {conf}{proof}",
        f"**Reward guidance:** {_BOUNTY_HINT.get(sev, 'varies')} *(indicative only - the program decides)*",
    ]
    if is_destructive(f.vuln_type):
        parts.append(
            "\n> ⚠️ **Destructive class** - confirming or exploiting this can write state or affect "
            "other users. Verify manually and follow the program's rules before active testing."
        )
    if prior_seen > 0:
        runs = "run" if prior_seen == 1 else "runs"
        parts.append(
            f"\n> ♻ **Seen before** - this bug matches a finding from {prior_seen} earlier {runs}. "
            "It may already be reported; check your submission history before filing (duplicates "
            "hurt your platform reputation)."
        )
    parts += [
        "",
        "## Summary",
        f.description or f"A {f.vuln_type} issue was identified on the affected asset.",
    ]
    if len(group.instances) > 1:
        locs = "\n".join(f"- `{i.url}`" + (f" (parameter `{i.parameter}`)" if i.parameter else "")
                         for i in group.instances[:25])
        parts += ["", f"**Affected locations ({len(group.instances)}):**", locs]

    parts += ["", "## Steps to Reproduce"]
    if f.parameter:
        parts.append(f"1. Target the `{f.parameter}` parameter at `{f.url}`.")
    parts.append("2. Send the request below; observe the indicator noted under Evidence.")
    if snippets:
        parts += [
            "",
            "```bash",
            snippets["curl"],
            "```",
            "",
            "<details><summary>Python / raw request (Burp Repeater)</summary>",
            "",
            "```python",
            snippets["python"],
            "```",
            "",
            "```http",
            snippets["raw"],
            "```",
            "</details>",
        ]
    else:
        parts.append(f"\nRequest the affected URL directly: `{f.url}`")

    impact = {
        "critical": "Full compromise of the asset or its data is achievable.",
        "high": "A remote attacker can seriously abuse this against users or data.",
        "medium": "Exploitable under realistic conditions with meaningful impact.",
        "low": "Limited impact; still weakens the asset's security posture.",
        "info": "Informational - hardening opportunity.",
    }.get(sev, "See summary.")
    parts += ["", "## Impact", impact]

    ev_bits = []
    if getattr(ev, "matched_at", None):
        ev_bits.append(f"- Indicator: `{str(ev.matched_at)[:300]}`")
    if getattr(ev, "notes", None):
        ev_bits.append(f"- {str(ev.notes)[:400]}")
    if getattr(ev, "response_raw", None):
        ev_bits.append("\n```http\n" + str(ev.response_raw)[:1500] + "\n```")
    if ev_bits:
        parts += ["", "## Evidence", *ev_bits]

    parts += ["", "## Remediation", f.remediation or "Apply standard mitigations for this class of issue.",
              "", "---",
              "_Generated by ORTHRUS. Verify against the program's rules before submitting; "
              "confirmation was performed non-destructively._"]
    return "\n".join(parts) + "\n"


def campaign_summary(report: CampaignReport, program_name: str = "", *,
                     prior_seen: dict[int, int] | None = None) -> dict:
    """A machine-readable view of the ranked bug queue (for automation/dashboards).

    Pure: the same deduped, priority-ranked queue the Markdown index shows, plus
    the filter counts and per-bug metadata - including ``prior_seen`` so a
    consumer can skip likely duplicates.
    """
    prior_seen = prior_seen or {}
    sev_counts: dict[str, int] = {}
    bugs = []
    for i, g in enumerate(report.groups, 1):
        f = g.lead
        s = _sev(f.severity)
        sev_counts[s] = sev_counts.get(s, 0) + 1
        bugs.append({
            "rank": i,
            "priority": priority_score(f),
            "severity": s,
            "confidence": _conf(f.confidence),
            "vuln_type": f.vuln_type,
            "title": _norm_title(f.title),
            "host": _host(f.url),
            "url": f.url,
            "cwe": f.cwe or None,
            "cvss": f.cvss_score,
            "instances": len(g.instances),
            "technique": g.technique,
            "prior_seen": prior_seen.get(id(f), 0),
        })
    return {
        "program": program_name or None,
        "reportable": report.reportable,
        "considered": report.considered,
        "out_of_scope": report.out_of_scope,
        "below_confidence": report.below_confidence,
        "suppressed": report.suppressed,
        "severity_counts": sev_counts,
        "bugs": bugs,
    }


def render_index(report: CampaignReport, program_name: str = "", *,
                 prior_seen: dict[int, int] | None = None) -> str:
    prior_seen = prior_seen or {}
    any_seen = False
    rows = []
    for i, g in enumerate(report.groups, 1):
        f = g.lead
        cvss = f.cvss_score if f.cvss_score is not None else "-"
        mark = " ♻" if prior_seen.get(id(f)) else ""
        any_seen = any_seen or bool(mark)
        rows.append(f"| {i} | {priority_score(f):.0f} | {_sev(f.severity).upper()} | "
                    f"{_norm_title(f.title)}{mark} | {cvss} | {_conf(f.confidence)} | `{_host(f.url)}` |")
    body = "\n".join(rows) or "| - | - | - | - | - | - | - |"
    sev_counts: dict[str, int] = {}
    for g in report.groups:
        s = _sev(g.lead.severity)
        sev_counts[s] = sev_counts.get(s, 0) + 1
    dist = " · ".join(f"{sev_counts.get(s, 0)} {s}" for s in ("critical", "high", "medium", "low", "info"))
    considered_line = (
        f"_{report.considered} findings considered · {report.out_of_scope} dropped as out-of-scope · "
        f"{report.below_confidence} below the confidence floor"
        + (f" · {report.suppressed} muted" if report.suppressed else "") + "._\n\n"
    )
    seen_note = ("_♻ = matched a finding from an earlier run (possible duplicate - verify before "
                 "filing)._\n\n" if any_seen else "")
    return (
        f"# Bug-bounty findings{f' - {program_name}' if program_name else ''}\n\n"
        f"**{report.reportable} reportable bug(s)** - {dist}.  \n"
        + considered_line
        + "| # | Priority | Severity | Bug | CVSS | Confidence | Asset |\n"
        "|---|---|---|---|---|---|---|\n" + body + "\n\n"
        + seen_note
        + "Each bug has its own submission-ready report in this folder. Always confirm the target is "
        "in the program's current scope and follow its disclosure rules before submitting.\n"
    )


__all__ = ["BugGroup", "CampaignReport", "select_and_group", "render_submission", "render_index",
           "campaign_summary"]
