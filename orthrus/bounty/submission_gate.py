"""Submission gate: predict how a mature bug-bounty program will triage a finding.

Scanners find *issues*; programs pay for *impact*. On a mature program, a whole
class of scanner output - missing security headers, non-credentialed CORS, cookie
flags on tracking cookies, unverified "shadow" paths - is routinely closed as
Informational / N/A, and submitting it burns the researcher's signal. This module
sorts findings into three buckets so the report leads with what actually pays:

* ``submit``     - impactful and evidenced; send it.
* ``borderline`` - real class, but impact must be proven first (or a caveat resolved).
* ``hold``       - almost always closed informational on a mature program.

It never *deletes* a finding - it labels and orders. Deciding to submit is always
the operator's call; this just stops the wheat drowning in chaff.
"""

from __future__ import annotations

from dataclasses import dataclass

from orthrus.bounty.triage import priority_score

SUBMIT = "submit"
BORDERLINE = "borderline"
HOLD = "hold"

# Impact-bearing classes that pay when evidenced.
_HIGH_VALUE_TYPES = frozenset({
    "broken-authorization", "idor", "sqli", "nosql-injection", "cmd-injection",
    "ssrf", "xxe", "ssti", "xss", "auth-bypass", "jwt", "deserialization",
    "file-upload", "account-takeover", "payment-tampering", "graphql-injection",
    "ldap-injection", "xpath-injection", "prototype-pollution", "race-condition",
    "business-logic", "mass-assignment", "privilege-escalation", "prompt-injection",
    "second-order-injection", "otp-security", "internal-ip-disclosure",
})

# Classes a mature program routinely closes as informational unless chained.
_INFORMATIONAL_TYPES = frozenset({
    "security-headers", "clickjacking", "banner", "version-disclosure",
    "tls", "cookie-security", "referrer-policy", "cache-deception-theoretical",
})

# Title fragments that mark a low-value observation even under a broader vuln_type.
_INFORMATIONAL_TITLE = (
    "missing content-security-policy", "x-content-type-options", "referrer-policy",
    "x-frame-options", "strict-transport-security", "permissions-policy",
    "without httponly", "without samesite", "without secure flag",
    "autocomplete", "verbose", "banner", "email spoof", "spf", "dmarc",
)


@dataclass(frozen=True)
class SubmissionVerdict:
    """Predicted triage outcome for one finding."""

    disposition: str          # submit | borderline | hold
    odds: str                 # human label: likely paid / needs impact proof / likely N/A
    reason: str
    score: float              # priority_score, for ordering within a bucket


def _text(finding) -> str:
    parts = [getattr(finding, "title", ""), getattr(finding, "vuln_type", "")]
    ev = getattr(finding, "evidence", None)
    if ev is not None:
        parts += [getattr(ev, "notes", "") or "", getattr(ev, "response_raw", "") or "",
                  getattr(ev, "request_raw", "") or ""]
    return " ".join(parts).lower()


def _conf(finding) -> str:
    return getattr(getattr(finding, "confidence", ""), "value", str(getattr(finding, "confidence", ""))).lower()


def _sev(finding) -> str:
    return getattr(getattr(finding, "severity", ""), "value", str(getattr(finding, "severity", ""))).lower()


def assess(finding) -> SubmissionVerdict:
    """Classify one finding into submit / borderline / hold with a reason."""
    vuln = (getattr(finding, "vuln_type", "") or "").lower()
    text = _text(finding)
    conf = _conf(finding)
    sev = _sev(finding)
    score = priority_score(finding)

    # 1) Explicitly low-value observations, regardless of the tool's severity.
    if vuln in _INFORMATIONAL_TYPES or any(frag in text for frag in _INFORMATIONAL_TITLE):
        return SubmissionVerdict(HOLD, "likely N/A",
                                 "commonly closed as informational on a mature program", score)

    # 2) CORS: only credentialed reflection has read impact.
    if vuln == "cors":
        if "allow-credentials: true" in text or "with credentials" in text:
            return SubmissionVerdict(SUBMIT, "likely paid",
                                     "credentialed CORS reflection can read authenticated data", score)
        return SubmissionVerdict(HOLD, "likely N/A",
                                 "no read impact without Access-Control-Allow-Credentials: true", score)

    # 3) Shadow API: a distinct body is a lead, but SPA catch-alls masquerade as 200.
    if vuln == "shadow-api":
        has_body = bool(getattr(getattr(finding, "evidence", None), "response_raw", ""))
        return SubmissionVerdict(
            BORDERLINE, "needs impact proof",
            "confirm it is real API surface (not an SPA catch-all) and find authz/data impact"
            + ("" if has_body else "; no response body captured"),
            score,
        )

    # 4) Impact-bearing classes: submit when confirmed/evidenced, else prove impact first.
    if vuln in _HIGH_VALUE_TYPES:
        has_sensitive = "sensitive data" in text or "accessible data included" in text
        if conf == "confirmed" or has_sensitive or (sev in ("critical", "high") and conf == "firm"):
            return SubmissionVerdict(SUBMIT, "likely paid",
                                     "impactful class with reproduced/evidenced impact", score)
        return SubmissionVerdict(BORDERLINE, "needs impact proof",
                                 "impactful class but impact not yet confirmed - verify by hand", score)

    # 5) Default: high-confidence highs are worth submitting; the rest are borderline.
    if sev in ("critical", "high") and conf in ("confirmed", "firm"):
        return SubmissionVerdict(SUBMIT, "likely paid", "high-severity, high-confidence finding", score)
    return SubmissionVerdict(BORDERLINE, "needs impact proof",
                             "verify exploitability and impact before submitting", score)


def partition(findings: list) -> dict[str, list]:
    """Group findings into submit / borderline / hold, each sorted by score desc."""
    buckets: dict[str, list] = {SUBMIT: [], BORDERLINE: [], HOLD: []}
    for finding in findings:
        verdict = assess(finding)
        buckets[verdict.disposition].append((finding, verdict))
    for items in buckets.values():
        items.sort(key=lambda pair: pair[1].score, reverse=True)
    return buckets


def summary_line(findings: list) -> str:
    """One-line tally, e.g. ``submit: 2 · borderline: 3 · hold: 13``."""
    buckets = partition(findings)
    return " · ".join(f"{name}: {len(buckets[name])}" for name in (SUBMIT, BORDERLINE, HOLD))


_HEADINGS = {
    SUBMIT: "Submit now (impactful + evidenced)",
    BORDERLINE: "Prove impact first",
    HOLD: "Hold - likely N/A on a mature program",
}


def render_overview(findings: list) -> str:
    """A markdown triage overview that leads with what actually pays.

    Lets the operator see, before writing a single report, which findings are
    worth a triager's time and which will be closed informational.
    """
    buckets = partition(findings)
    lines = ["## Submission triage", "", f"_{summary_line(findings)}_", ""]
    for bucket in (SUBMIT, BORDERLINE, HOLD):
        rows = buckets[bucket]
        lines.append(f"### {_HEADINGS[bucket]} ({len(rows)})")
        if not rows:
            lines += ["", "_none_", ""]
            continue
        lines.append("")
        for finding, verdict in rows:
            title = getattr(finding, "title", "(untitled)")
            sev = _sev(finding).upper()
            lines.append(f"- **[{sev}]** {title} - _{verdict.odds}: {verdict.reason}_")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


__all__ = ["SubmissionVerdict", "assess", "partition", "summary_line", "render_overview",
           "SUBMIT", "BORDERLINE", "HOLD"]
