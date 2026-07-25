"""CWE -> HackerOne weakness mapping + coverage-completeness guard."""

from __future__ import annotations

import glob
import re

from orthrus.bounty.weakness import (
    OUT_OF_SCOPE,
    WEAKNESS_LABELS,
    covered_cwes,
    weakness_label,
)


def test_weakness_label_format_and_fallback():
    assert weakness_label("CWE-79") == "Cross-site Scripting (XSS) (cwe-79)"
    assert weakness_label("cwe-918") == "Server-Side Request Forgery (SSRF) (cwe-918)"
    assert weakness_label("CWE-99999") == "CWE-99999"   # unknown -> bare id (still selectable)
    assert weakness_label(None) == "n/a" and weakness_label("") == "n/a"


def test_covered_cwes_sorted_numerically():
    ids = covered_cwes()
    assert ids[0] == "CWE-16" and "CWE-1427" in ids
    assert [int(c.split("-")[1]) for c in ids] == sorted(int(c.split("-")[1]) for c in ids)


def test_out_of_scope_families_are_documented():
    # The honest boundary must be stated (memory/hardware/network/wireless/mobile/physical).
    assert len(OUT_OF_SCOPE) >= 5
    assert any("memory" in k.lower() for k in OUT_OF_SCOPE)


def test_every_emitted_cwe_is_mapped():
    """Regression guard: a new scanner CWE that isn't in WEAKNESS_LABELS fails here."""
    emitted: set[str] = set()
    for path in glob.glob("orthrus/**/*.py", recursive=True):
        with open(path, encoding="utf-8") as fh:
            emitted |= set(re.findall(r'cwe="(CWE-[0-9]+)"', fh.read()))
    unmapped = sorted(emitted - set(WEAKNESS_LABELS))
    assert unmapped == [], f"scanners emit CWEs missing from weakness.py: {unmapped}"


def test_hackerone_template_uses_the_readable_label():
    from orthrus.bounty import platforms
    from orthrus.bounty.report import BugGroup
    from orthrus.core.schemas import Confidence, Evidence, Finding, Severity

    finding = Finding(
        vuln_type="xss", title="Reflected XSS", severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED, url="https://t/x", cwe="CWE-79",
        parameter="q", evidence=Evidence(request_raw="GET /x?q=<script>"),
    )
    out = platforms.render(BugGroup(lead=finding, instances=[finding]),
                           platform="hackerone", program_name="acme")
    assert "Cross-site Scripting (XSS) (cwe-79)" in out
