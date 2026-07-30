"""Tests for deterministic, exploitability-first P1-P4 prioritisation."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.risk import RiskContext, assess_priority, priority_band
from orthrus.risk.priority import BAND_MEANING


def _f(severity="medium", confidence="tentative", *, kev=False, epss=None):
    ns = SimpleNamespace(severity=severity, confidence=confidence)
    if kev:
        ns.kev = True
    if epss is not None:
        ns.epss = epss
    return ns


INTERNET = RiskContext(internet_facing=True)
INTERNAL = RiskContext(internet_facing=False, asset_criticality="low")


def test_confirmed_exploited_exposed_critical_is_p1():
    a = assess_priority(
        _f("critical", "confirmed", kev=True, epss=0.9),
        RiskContext(asset_criticality="critical", internet_facing=True),
    )
    assert a.band == "P1" and a.score == 100.0
    assert any("KEV" in r for r in a.rationale)


def test_tentative_info_internal_is_p4():
    a = assess_priority(_f("info", "tentative"), INTERNAL)
    assert a.band == "P4"


def test_kev_is_monotonic():
    ctx = INTERNET
    without = assess_priority(_f("medium", "firm"), ctx).score
    with_kev = assess_priority(_f("medium", "firm", kev=True), ctx).score
    assert with_kev > without


def test_confirmed_medium_can_outrank_tentative_high():
    # The whitepaper's thesis: exploitability + context beat raw severity.
    confirmed_med = assess_priority(
        _f("medium", "confirmed", kev=True), RiskContext(asset_criticality="high")
    )
    tentative_high = assess_priority(_f("high", "tentative"), INTERNAL)
    assert confirmed_med.score > tentative_high.score
    assert confirmed_med.band == "P1" and tentative_high.band in ("P3", "P4")


def test_compensating_controls_can_lower_the_band():
    finding = _f("high", "firm")
    exposed = assess_priority(finding, RiskContext(internet_facing=True))
    mitigated = assess_priority(
        finding, RiskContext(internet_facing=True, compensating_controls=30.0)
    )
    assert mitigated.score < exposed.score
    assert mitigated.band != "P1" or exposed.band == "P1"  # controls never raise risk


def test_epss_scales_the_score():
    low = assess_priority(_f("medium", "firm", epss=0.01), INTERNET).score
    high = assess_priority(_f("medium", "firm", epss=0.95), INTERNET).score
    assert high - low >= 20  # ~0.94 * 25


def test_all_four_bands_are_reachable():
    bands = {
        assess_priority(_f("critical", "confirmed", kev=True), INTERNET).band,
        assess_priority(_f("high", "firm"), INTERNET).band,
        assess_priority(_f("medium", "tentative"), INTERNET).band,
        assess_priority(_f("info", "tentative"), INTERNAL).band,
    }
    assert bands == {"P1", "P2", "P3", "P4"}


def test_deterministic_same_evidence_same_band():
    finding, ctx = _f("high", "confirmed", kev=True, epss=0.4), INTERNET
    first = assess_priority(finding, ctx)
    second = assess_priority(finding, ctx)
    assert (first.band, first.score, first.rationale) == (second.band, second.score, second.rationale)


def test_missing_enrichment_attrs_do_not_crash():
    bare = SimpleNamespace(severity="high", confidence="firm")  # no epss/kev/cvss
    a = assess_priority(bare)
    assert a.band in {"P1", "P2", "P3", "P4"}


def test_priority_band_convenience_and_meaning():
    assert priority_band(_f("info", "tentative"), INTERNAL) == "P4"
    a = assess_priority(_f("critical", "confirmed", kev=True), INTERNET)
    assert a.meaning == BAND_MEANING["P1"]
    assert a.rationale[-1].endswith("P1")
