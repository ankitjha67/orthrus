"""Vuln-class ontology: governance metadata + report caution."""

from __future__ import annotations

from orthrus.bounty.ontology import (
    ONTOLOGY_VERSION,
    class_info,
    confidence_ceiling,
    is_destructive,
)
from orthrus.bounty.report import render_submission, select_and_group
from orthrus.bounty.scope_intake import parse_program_scope
from orthrus.core.schemas import Confidence, Finding, Severity


def test_class_info_defaults_and_governance():
    assert ONTOLOGY_VERSION == "1.0.0"
    sqli = class_info("sqli")
    assert sqli.category == "injection" and sqli.confidence_ceiling == "confirmed"
    assert sqli.destructive is False

    assert is_destructive("mass-assignment") is True
    assert is_destructive("stored-xss") is True
    assert confidence_ceiling("business-logic") == "firm"   # no safe generic active proof
    assert confidence_ceiling("race-condition") == "firm"

    unknown = class_info("brand-new-thing")                  # safe default
    assert unknown.category == "other" and unknown.confidence_ceiling == "confirmed"
    assert unknown.destructive is False


def _bug(vt):
    ps = parse_program_scope("*.example.com\n")
    f = Finding(vuln_type=vt, title=f"{vt} issue", severity=Severity.HIGH,
                confidence=Confidence.FIRM, url="https://a.example.com/x")
    return select_and_group([f], ps, min_confidence="firm").groups[0]


def test_report_flags_destructive_class():
    assert "Destructive class" in render_submission(_bug("stored-xss"))
    assert "Destructive class" not in render_submission(_bug("sqli"))
