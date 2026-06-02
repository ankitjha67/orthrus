"""Finding triage: URL templating, dedup/clustering, LLM prompt/parse."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.triage import (
    build_triage_prompt,
    dedup_key,
    parse_judge_response,
    template_url,
    triage_findings,
)


def F(vuln_type, url, severity="medium", parameter=None, title=None, notes=""):
    return SimpleNamespace(
        vuln_type=vuln_type, url=url, severity=severity, parameter=parameter,
        title=title or vuln_type, evidence=SimpleNamespace(notes=notes),
    )


# ----------------------------------------------------------- url templating
def test_template_url_folds_id_segments():
    assert template_url("https://x.com/order/8412") == "https://x.com/order/{id}"
    assert template_url("https://x.com/u/3f9a2b8c1d") == "https://x.com/u/{id}"
    assert template_url("https://x.com/about/team") == "https://x.com/about/team"


def test_template_url_drops_query():
    assert template_url("https://x.com/search?q=1&p=2") == "https://x.com/search"


def test_dedup_key_matches_across_ids():
    a = F("idor", "https://x.com/order/1")
    b = F("idor", "https://x.com/order/9999")
    assert dedup_key(a) == dedup_key(b)


# ------------------------------------------------------------- triage core
def test_triage_collapses_duplicates():
    findings = [F("idor", f"https://x.com/order/{i}", "high") for i in range(1, 6)]
    report = triage_findings(findings)
    assert report.total == 5 and report.unique == 1 and report.collapsed == 4
    c = report.clusters[0]
    assert c.template == "https://x.com/order/{id}" and c.count == 5
    assert len(c.urls) == 5
    assert "5 finding(s)" in report.summary()


def test_triage_keeps_distinct_issues_and_max_severity():
    findings = [
        F("idor", "https://x.com/order/1", "low"),
        F("idor", "https://x.com/order/2", "high"),    # same cluster, higher sev wins
        F("xss", "https://x.com/search", "medium"),    # distinct cluster
    ]
    report = triage_findings(findings)
    assert report.unique == 2
    idor = next(c for c in report.clusters if c.vuln_type == "idor")
    assert idor.severity == "high" and idor.count == 2
    # critical/high clusters sort before lower ones
    assert report.clusters[0].severity == "high"


def test_triage_empty():
    report = triage_findings([])
    assert report.total == 0 and report.unique == 0


# --------------------------------------------------------------- LLM judge
def test_build_triage_prompt_includes_key_fields():
    report = triage_findings([F("sqli", "https://x.com/login", "critical", "user", notes="boolean-based")])
    prompt = build_triage_prompt(report.clusters[0])
    assert "sqli" in prompt and "critical" in prompt
    assert "boolean-based" in prompt and "false_positive" in prompt


def test_parse_judge_response_valid_and_invalid():
    v = parse_judge_response('{"false_positive": true, "confidence": "high", "rationale": "reflected only"}')
    assert v.is_false_positive is True and v.confidence == "high"
    # tolerant of surrounding prose
    v2 = parse_judge_response('Verdict: {"false_positive": false, "confidence": "medium"} done')
    assert v2.is_false_positive is False and v2.confidence == "medium"
    assert parse_judge_response("no json at all") is None
    assert parse_judge_response('{"other": 1}') is None  # missing required key


def test_parse_judge_response_clamps_confidence():
    v = parse_judge_response('{"false_positive": true, "confidence": "totally"}')
    assert v.confidence == "low"  # unknown confidence clamped
