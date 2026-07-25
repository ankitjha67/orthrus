"""Platform-native bounty report templates."""

from __future__ import annotations

import pytest

from orthrus.bounty.platforms import PLATFORMS, render
from orthrus.bounty.report import BugGroup
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity


def _group(sev=Severity.HIGH) -> BugGroup:
    f = Finding(
        vuln_type="sqli", title="SQL injection", severity=sev, confidence=Confidence.CONFIRMED,
        url="https://api.example.com/item?id=1", parameter="id", cwe="CWE-89",
        cvss_score=9.8, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        remediation="Use parameterized queries.",
        evidence=Evidence(request_raw="GET /item?id=1 HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
                          matched_at="SQL syntax error"),
    )
    return BugGroup(lead=f, instances=[f], technique="error-based replay")


def test_every_platform_renders_core_facts():
    g = _group()
    for platform in PLATFORMS:
        md = render(g, platform=platform, program_name="Acme")
        assert "SQL injection" in md
        assert "cwe-89" in md.lower()   # HackerOne uses the dropdown label "... (cwe-89)"
        assert "9.8" in md
        assert "curl -sk" in md            # reproduction snippet embedded everywhere
        assert md.strip().startswith("#")  # a real report


def test_platform_specific_shapes():
    g = _group()
    h1 = render(g, platform="hackerone")
    assert "**Weakness:**" in h1 and "## Steps To Reproduce" in h1 and "Supporting Material" in h1

    bc = render(g, platform="bugcrowd")
    assert "**Priority:** P2" in bc and "VRT" in bc  # high -> P2

    intg = render(g, platform="intigriti")
    assert "## Proof of concept" in intg and "## Recommendation" in intg

    ywh = render(g, platform="yeswehack")
    assert "**Bug type:**" in ywh and "## Steps to reproduce" in ywh

    im = render(g, platform="immunefi")
    assert "public GitHub gist" in im and "## Proof of Concept" in im


def test_bugcrowd_priority_maps_severity():
    assert "**Priority:** P1" in render(_group(Severity.CRITICAL), platform="bugcrowd")
    assert "**Priority:** P4" in render(_group(Severity.LOW), platform="bugcrowd")


def test_generic_falls_back_to_submission_report():
    md = render(_group(), platform="generic")
    assert "## Steps to Reproduce" in md and "## Impact" in md and "Reward guidance" in md


@pytest.mark.parametrize("bad", ["", "unknownplatform", None])
def test_unknown_platform_is_generic(bad):
    md = render(_group(), platform=bad)  # type: ignore[arg-type]
    assert "Reward guidance" in md  # the generic report's signature line
