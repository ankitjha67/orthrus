"""Tests for the deterministic, traceable finding-policy engine."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from orthrus.risk.policy import (
    ESCALATE,
    KEEP,
    SUPPRESS,
    Policy,
    apply_policies,
    default_policies,
    evaluate,
)


def _f(vuln_type="xss", severity="high", confidence="firm", *, kev=False, url="https://t/a", title="T"):
    ns = SimpleNamespace(vuln_type=vuln_type, severity=severity, confidence=confidence, url=url, title=title)
    if kev:
        ns.kev = True
    return ns


# --- Policy.matches ------------------------------------------------------------

def test_empty_policy_matches_nothing():
    assert Policy("noop").matches(_f()) is False


def test_all_set_conditions_must_hold():
    p = Policy("p", SUPPRESS, vuln_types=("xss",), severity_below="high")
    assert p.matches(_f(vuln_type="xss", severity="low")) is True
    assert p.matches(_f(vuln_type="xss", severity="high")) is False  # severity fails
    assert p.matches(_f(vuln_type="sqli", severity="low")) is False  # vuln_type fails


def test_severity_and_kev_conditions():
    assert Policy("p", severity_at_least="high").matches(_f(severity="critical"))
    assert not Policy("p", severity_at_least="high").matches(_f(severity="medium"))
    assert Policy("p", kev=True).matches(_f(kev=True))
    assert not Policy("p", kev=True).matches(_f(kev=False))


def test_host_and_title_substring():
    assert Policy("p", host_contains="api.").matches(_f(url="https://api.t/x"))
    assert Policy("p", title_contains="spf").matches(_f(title="No SPF record"))


def test_from_dict_and_invalid_action():
    p = Policy.from_dict({"name": "x", "action": "suppress", "vuln_types": ["tls"]})
    assert p.action == SUPPRESS and p.vuln_types == ("tls",)
    with pytest.raises(ValueError):
        Policy.from_dict({"name": "bad", "action": "delete"})


# --- evaluate (ordered, traceable) ---------------------------------------------

def test_default_policies_decisions():
    pols = default_policies()
    # KEV escalates and beats everything (lowest priority number).
    kev = evaluate(_f(severity="low", confidence="tentative", kev=True), pols)
    assert kev.verdict == ESCALATE and kev.policy == "kev-escalate"
    # A confirmed finding is always kept.
    assert evaluate(_f(severity="medium", confidence="confirmed"), pols).verdict == KEEP
    # Tentative below high is suppressed, with a traceable policy + reason.
    low = evaluate(_f(severity="medium", confidence="tentative"), pols)
    assert low.verdict == SUPPRESS and low.policy == "tentative-below-high" and low.reason


def test_first_matching_policy_wins_by_priority():
    pols = [
        Policy("late", KEEP, priority=90, vuln_types=("xss",)),
        Policy("early", SUPPRESS, priority=10, vuln_types=("xss",)),
    ]
    d = evaluate(_f(vuln_type="xss"), pols)
    assert d.verdict == SUPPRESS and d.policy == "early"


def test_default_keep_when_no_policy_matches():
    d = evaluate(_f(vuln_type="sqli"), [Policy("only-xss", SUPPRESS, vuln_types=("xss",))])
    assert d.verdict == KEEP and d.policy == "default"


def test_evaluate_is_deterministic():
    f, pols = _f(severity="medium", confidence="tentative"), default_policies()
    a, b = evaluate(f, pols), evaluate(f, pols)
    assert (a.verdict, a.policy, a.reason) == (b.verdict, b.policy, b.reason)


def test_apply_policies_partitions_with_decisions():
    pols = default_policies()
    findings = [
        _f(confidence="confirmed"),                      # keep
        _f(severity="low", confidence="tentative"),      # suppress
        _f(severity="low", confidence="tentative", kev=True),  # escalate (KEV)
    ]
    buckets = apply_policies(findings, pols)
    assert len(buckets[KEEP]) == 1 and len(buckets[SUPPRESS]) == 1 and len(buckets[ESCALATE]) == 1
    # every item carries its deciding decision (traceable)
    for items in buckets.values():
        for _finding, decision in items:
            assert decision.policy and decision.reason
