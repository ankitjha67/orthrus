"""Tests for the pure email-authentication (SPF/DMARC/DKIM) verdict logic."""

from __future__ import annotations

from orthrus.bounty.weakness import weakness_label
from orthrus.core.schemas import Severity
from orthrus.scanners.email_auth import (
    _dmarc_candidates,
    _dmarc_pct,
    _dmarc_tag,
    _spf_all_qualifier,
    classify_email_auth,
)


def _titles(issues) -> set[str]:
    return {t for _s, t, _d, _c, _r in issues}


def _by_title(issues, needle):
    return next((i for i in issues if needle.lower() in i[1].lower()), None)


# --- helper parsing ------------------------------------------------------------

def test_spf_all_qualifier():
    assert _spf_all_qualifier("v=spf1 include:_spf.google.com -all") == "-"
    assert _spf_all_qualifier("v=spf1 ~all") == "~"
    assert _spf_all_qualifier("v=spf1 ?all") == "?"
    assert _spf_all_qualifier("v=spf1 +all") == "+"
    assert _spf_all_qualifier("v=spf1 mx all") == "+"   # bare 'all' defaults to pass
    assert _spf_all_qualifier("v=spf1 include:x.com") is None


def test_dmarc_tag_and_pct():
    rec = "v=DMARC1; p=reject; sp=none; pct=50; rua=mailto:d@x.com"
    assert _dmarc_tag(rec, "p") == "reject"
    assert _dmarc_tag(rec, "sp") == "none"
    assert _dmarc_tag(rec, "rua") == "mailto:d@x.com"
    assert _dmarc_tag(rec, "fo") is None
    assert _dmarc_pct(rec) == 50
    assert _dmarc_pct("v=DMARC1; p=none") is None


def test_dmarc_candidates_walks_up_to_org_domain():
    assert _dmarc_candidates("www.example.com") == ["www.example.com", "example.com"]
    assert _dmarc_candidates("example.com") == ["example.com"]
    # multi-part TLDs: the real org domain is queried before the public suffix.
    assert "example.co.uk" in _dmarc_candidates("mail.example.co.uk")


# --- classification ------------------------------------------------------------

def test_missing_spf_and_dmarc_are_both_flagged():
    issues = classify_email_auth({"spf": None, "dmarc": None})
    assert _by_title(issues, "No SPF record")[0] is Severity.LOW
    dmarc = _by_title(issues, "No DMARC record")
    assert dmarc is not None and dmarc[0] is Severity.MEDIUM and dmarc[3] == "CWE-290"


def test_permissive_spf_is_medium():
    for spf in ("v=spf1 +all", "v=spf1 ?all"):
        issue = _by_title(classify_email_auth({"spf": spf, "dmarc": "v=DMARC1; p=reject"}), "permissive")
        assert issue is not None and issue[0] is Severity.MEDIUM and issue[3] == "CWE-290"


def test_dmarc_p_none_is_monitor_only():
    issue = _by_title(classify_email_auth({"spf": "v=spf1 -all", "dmarc": "v=DMARC1; p=none"}), "monitor-only")
    assert issue is not None and issue[0] is Severity.MEDIUM and issue[3] == "CWE-290"


def test_enforcing_dmarc_with_hardfail_spf_is_clean():
    issues = classify_email_auth({"spf": "v=spf1 include:_spf.google.com -all",
                                  "dmarc": "v=DMARC1; p=reject; pct=100"})
    assert all(s in (Severity.INFO,) for s, *_ in issues)  # nothing MEDIUM/HIGH
    assert not _by_title(issues, "spoofable")
    assert not _by_title(issues, "monitor-only")


def test_multiple_spf_is_permerror():
    issue = _by_title(classify_email_auth({"spf": "v=spf1 -all", "spf_count": 2}), "permerror")
    assert issue is not None and issue[0] is Severity.LOW


def test_subdomain_policy_none_and_partial_pct():
    issues = classify_email_auth({"spf": "v=spf1 -all", "dmarc": "v=DMARC1; p=reject; sp=none; pct=25"})
    assert _by_title(issues, "sp=none")[0] is Severity.LOW
    assert _by_title(issues, "pct=25")[0] is Severity.LOW


def test_dkim_absence_is_informational():
    issue = _by_title(
        classify_email_auth({"spf": "v=spf1 -all", "dmarc": "v=DMARC1; p=reject",
                             "dkim_checked": True, "dkim_selectors_found": []}),
        "No DKIM",
    )
    assert issue is not None and issue[0] is Severity.INFO


def test_mx_presence_sharpens_the_description():
    with_mx = classify_email_auth({"dmarc": None, "mx": ["mx.example.com"]})
    assert "actively receives mail" in _by_title(with_mx, "No DMARC")[2]


def test_cwe_290_is_mapped_for_submission():
    # Guards the weakness.py addition so a spoofing finding renders a readable label.
    assert weakness_label("CWE-290") == "Authentication Bypass by Spoofing (cwe-290)"
