"""CVE threat-intelligence enrichment (CISA KEV + EPSS)."""

from __future__ import annotations

from orthrus.core.schemas import Severity
from orthrus.intel import cve_intel
from orthrus.intel.cve_intel import enrich, escalate_severity, refresh_kev, summary


def test_enrich_known_kev_and_epss() -> None:
    intel = enrich("CVE-2021-44228")  # Log4Shell — KEV + high EPSS
    assert intel.kev is True
    assert intel.epss is not None and intel.epss > 0.9
    assert intel.has_intel is True


def test_enrich_is_case_insensitive() -> None:
    assert enrich("cve-2021-44228").kev is True


def test_enrich_unknown_cve() -> None:
    intel = enrich("CVE-2099-0001")
    assert intel.kev is False
    assert intel.epss is None
    assert intel.has_intel is False


def test_kev_escalates_severity_to_high() -> None:
    kev = enrich("CVE-2021-44228")
    assert escalate_severity(Severity.MEDIUM, kev) == Severity.HIGH
    assert escalate_severity(Severity.LOW, kev) == Severity.HIGH
    assert escalate_severity(Severity.CRITICAL, kev) == Severity.CRITICAL  # not downgraded


def test_non_kev_does_not_escalate() -> None:
    plain = enrich("CVE-2099-0001")
    assert escalate_severity(Severity.MEDIUM, plain) == Severity.MEDIUM


def test_summary_text() -> None:
    s = summary(enrich("CVE-2021-44228"))
    assert "KEV" in s and "EPSS" in s
    assert summary(enrich("CVE-2099-0001")) == ""


def test_refresh_kev_roundtrip() -> None:
    # Back up the shipped seed (file bytes + in-memory set) and restore afterwards
    # so refresh_kev never mutates the committed catalog.
    with open(cve_intel._KEV_FILE, "rb") as fh:
        original_bytes = fh.read()
    original_kev = set(cve_intel._KEV)
    try:
        feed = {"vulnerabilities": [{"cveID": "CVE-2021-44228"}, {"cveID": "CVE-2030-9999"}]}
        assert refresh_kev(feed) == 2
        assert enrich("CVE-2030-9999").kev is True
    finally:
        with open(cve_intel._KEV_FILE, "wb") as fh:
            fh.write(original_bytes)
        cve_intel._KEV.clear()
        cve_intel._KEV.update(original_kev)
