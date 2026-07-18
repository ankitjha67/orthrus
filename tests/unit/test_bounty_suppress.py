"""Per-program mute rules + campaign-report suppression."""

from __future__ import annotations

import pytest

from orthrus.bounty.report import select_and_group
from orthrus.bounty.suppress import (
    SuppressionStore,
    make_rule,
    matching_rule,
    rule_matches,
)
from orthrus.core.schemas import Confidence, Finding, Severity


def _f(vuln_type="xss", url="https://api.acme.com/x", title="Reflected XSS", conf=Confidence.FIRM):
    return Finding(vuln_type=vuln_type, title=title, severity=Severity.MEDIUM,
                   confidence=conf, url=url)


class _Scope:
    def is_in_scope(self, host):  # accept everything; scope is tested elsewhere
        return True


def test_empty_rule_is_refused():
    with pytest.raises(ValueError):
        make_rule()  # no criteria -> would mute everything


def test_empty_rule_never_matches():
    assert rule_matches({}, _f()) is False


def test_vuln_type_and_host_subdomain_match():
    rule = make_rule(vuln_type="security-headers", host="acme.com")
    assert rule_matches(rule, _f(vuln_type="security-headers", url="https://api.acme.com/")) is True
    assert rule_matches(rule, _f(vuln_type="xss", url="https://api.acme.com/")) is False       # type differs
    assert rule_matches(rule, _f(vuln_type="security-headers", url="https://evil.com/")) is False  # host differs


def test_title_contains_is_case_insensitive():
    rule = make_rule(title_contains="marketing")
    assert matching_rule([rule], _f(title="XSS on Marketing site")) is rule
    assert matching_rule([rule], _f(title="XSS on api")) is None


def test_store_roundtrip_and_remove(tmp_path):
    store = SuppressionStore(tmp_path / "supp.json")
    store.add("acme", make_rule(vuln_type="cors", reason="accepted risk"))
    store.add("acme", make_rule(host="marketing.acme.com"))
    assert len(store.rules("acme")) == 2
    assert store.rules("other") == []
    assert store.remove("acme", 0) is True
    assert len(store.rules("acme")) == 1
    assert store.remove("acme", 9) is False


def test_select_and_group_counts_suppressed():
    findings = [
        _f(vuln_type="security-headers", url="https://a.acme.com/", title="Missing HSTS"),
        _f(vuln_type="xss", url="https://a.acme.com/s", title="Reflected XSS"),
    ]
    rules = [make_rule(vuln_type="security-headers")]
    report = select_and_group(findings, _Scope(), min_confidence="firm", suppressions=rules)
    assert report.suppressed == 1
    assert report.reportable == 1
    assert report.groups[0].lead.vuln_type == "xss"
    # without the rule, both are reportable
    plain = select_and_group(findings, _Scope(), min_confidence="firm")
    assert plain.suppressed == 0 and plain.reportable == 2
