"""Submission gate: predicts triage outcome, leads with payable findings.

Uses the exact finding classes from the real 1win report (non-credentialed CORS,
missing headers, cookie flags, unverified shadow-api) to prove the gate holds the
noise, plus a BOLA-with-PII to prove it surfaces the payable finding.
"""

from __future__ import annotations

from orthrus.bounty.submission_gate import (
    BORDERLINE,
    HOLD,
    SUBMIT,
    assess,
    partition,
    render_overview,
    summary_line,
)
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity


def _f(vuln_type: str, title: str, *, severity=Severity.MEDIUM, confidence=Confidence.FIRM,
       notes: str = "", response_raw: str = "") -> Finding:
    return Finding(
        vuln_type=vuln_type, title=title, severity=severity, confidence=confidence,
        url="https://t/x", evidence=Evidence(notes=notes, response_raw=response_raw),
    )


def test_non_credentialed_cors_is_held():
    v = assess(_f("cors", "CORS reflects arbitrary Origin",
                  notes="Access-Control-Allow-Credentials: false"))
    assert v.disposition == HOLD and v.odds == "likely N/A"


def test_credentialed_cors_is_submittable():
    v = assess(_f("cors", "CORS reflects arbitrary Origin",
                  confidence=Confidence.CONFIRMED,
                  notes="Access-Control-Allow-Credentials: true"))
    assert v.disposition == SUBMIT


def test_missing_headers_and_cookie_flags_are_held():
    assert assess(_f("security-headers", "Missing Content-Security-Policy header")).disposition == HOLD
    assert assess(_f("auth-session", "Cookie set without SameSite attribute ('device-id')",
                     severity=Severity.LOW)).disposition == HOLD


def test_shadow_api_is_borderline_with_caveat():
    v = assess(_f("shadow-api", "Undocumented API surface reachable"))
    assert v.disposition == BORDERLINE
    assert "catch-all" in v.reason


def test_bola_with_pii_is_top_submit():
    v = assess(_f("broken-authorization",
                  "Broken object-level authorization: 'user' reached 'admin's resource",
                  severity=Severity.CRITICAL, confidence=Confidence.FIRM,
                  notes="sensitive data exposed: email=a***@***.example, money=USD 4200"))
    assert v.disposition == SUBMIT and v.odds == "likely paid"


def test_unconfirmed_impactful_class_is_borderline():
    v = assess(_f("idor", "Possible IDOR", severity=Severity.MEDIUM, confidence=Confidence.TENTATIVE))
    assert v.disposition == BORDERLINE


def test_partition_orders_and_tallies_like_the_1win_report():
    findings = [
        _f("cors", "CORS reflects arbitrary Origin", notes="Access-Control-Allow-Credentials: false"),
        _f("cors", "CORS trusts null origin", notes="Access-Control-Allow-Credentials: false"),
        _f("security-headers", "Missing Content-Security-Policy header"),
        _f("shadow-api", "Undocumented API surface reachable: /resources/v2/app/"),
        _f("auth-session", "Cookie set without HttpOnly flag ('cdn_cache_id')", severity=Severity.LOW),
        _f("broken-authorization", "Broken object-level authorization: 'user' reached 'admin's resource",
           severity=Severity.CRITICAL, confidence=Confidence.FIRM,
           notes="sensitive data exposed: email=a***@***.example"),
    ]
    buckets = partition(findings)
    assert len(buckets[SUBMIT]) == 1 and buckets[SUBMIT][0][0].vuln_type == "broken-authorization"
    assert len(buckets[BORDERLINE]) == 1                    # shadow-api
    assert len(buckets[HOLD]) == 4                          # 2 cors + headers + cookie
    assert summary_line(findings) == "submit: 1 · borderline: 1 · hold: 4"


def test_render_overview_leads_with_submit():
    findings = [
        _f("security-headers", "Missing Content-Security-Policy header"),
        _f("broken-authorization", "Broken object-level authorization",
           severity=Severity.CRITICAL, confidence=Confidence.FIRM, notes="sensitive data exposed: email"),
    ]
    md = render_overview(findings)
    assert "## Submission triage" in md
    # the submit bucket (and its heading) appears before the hold bucket
    assert md.index("Submit now") < md.index("Hold -")
    assert "Broken object-level authorization" in md
