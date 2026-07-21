"""Centralized payload corpora + the detectors that consume them.

These guard the shape and breadth of orthrus.scanners._payloads (so a future
edit can't silently drop a DBMS / OS / cloud / template-engine variant), and
the invariants the scanners rely on - most importantly that no SSRF metadata
*payload URL* contains a signature the detector matches (which would turn a mere
reflection into a false positive).
"""

from __future__ import annotations

from orthrus.scanners._payloads import (
    LFI_PATHS,
    SQLI_BOOLEAN_PAIRS,
    SQLI_ERROR,
    SQLI_TIME,
    SSRF_METADATA,
    cmd_output_payloads,
    cmd_time_payloads,
    ssti_templates,
    xss_execution_payloads,
)
from orthrus.scanners.cmd_injection import cmd_executed
from orthrus.scanners.lfi import detect_lfi
from orthrus.scanners.ssrf import detect_metadata_leak
from orthrus.scanners.ssti import ssti_evaluated


# ----------------------------------------------------------------------- SQLi
def test_sqli_error_payloads_are_unique_and_have_quote() -> None:
    assert "'" in SQLI_ERROR
    assert len(SQLI_ERROR) == len(set(SQLI_ERROR))
    assert len(SQLI_ERROR) >= 10


def test_sqli_boolean_pairs_diverge_true_from_false() -> None:
    labels = [label for label, _, _ in SQLI_BOOLEAN_PAIRS]
    assert len(labels) == len(set(labels))  # unique labels
    for _label, true_suffix, false_suffix in SQLI_BOOLEAN_PAIRS:
        assert true_suffix != false_suffix
    # string, numeric and parenthesised contexts are all represented
    assert {"string-quote", "numeric", "paren-string"} <= set(labels)


def test_sqli_time_payloads_cover_major_dbms_and_have_placeholder() -> None:
    dbms = {name for name, _ in SQLI_TIME}
    assert {"MySQL", "PostgreSQL", "Microsoft SQL Server", "Oracle"} <= dbms
    for _name, template in SQLI_TIME:
        assert "{n}" in template  # parameterised sleep duration


# ------------------------------------------------------------------------ LFI
def test_lfi_paths_cover_nix_and_windows_with_encodings() -> None:
    joined = "\n".join(LFI_PATHS)
    assert "../../../../../../../../etc/passwd" in LFI_PATHS  # plain *nix traversal
    assert "C:\\windows\\win.ini" in LFI_PATHS  # plain Windows
    assert "%2f" in joined  # at least one percent-encoded variant
    assert "%252f" in joined  # at least one double-encoded variant
    assert "%00" in joined  # null-byte truncation variant


def test_lfi_detector_unaffected_by_corpus() -> None:
    assert detect_lfi("root:x:0:0:root:/root:/bin/bash") == "/etc/passwd"
    assert detect_lfi("nothing useful here") is None


# --------------------------------------------------------------- command inj.
def test_cmd_output_payloads_embed_echo_and_cover_separators() -> None:
    payloads = cmd_output_payloads("v", "CANARY123")
    assert all("echo CANARY123" in p for p in payloads)
    blob = "\n".join(payloads)
    for sep in (";", "|", "&&", "`", "$("):
        assert sep in blob


def test_cmd_executed_distinguishes_output_from_reflection() -> None:
    # Reflected payload (the literal "echo CANARY") must NOT count as execution.
    assert cmd_executed("CANARY123", "you said: echo CANARY123") is False
    # The canary alone is command output -> execution.
    assert cmd_executed("CANARY123", "CANARY123\n") is True


def test_cmd_time_payloads_cover_posix_and_windows() -> None:
    payloads = cmd_time_payloads("v", 5)
    blob = "\n".join(payloads)
    assert "sleep 5" in blob  # POSIX
    assert "ping -n 6" in blob  # Windows ping delay
    assert "timeout /t 5" in blob  # Windows timeout


# ----------------------------------------------------------------------- SSTI
def test_ssti_templates_cover_multiple_engines() -> None:
    pairs = ssti_templates("7*7")
    labels = " ".join(label for label, _ in pairs)
    for engine in ("Jinja2", "ERB", "Razor", "Velocity", "Thymeleaf"):
        assert engine in labels
    # Every payload embeds the expression verbatim.
    assert all("7*7" in payload for _label, payload in pairs)


def test_ssti_velocity_payload_detects_via_product() -> None:
    # The Velocity engine renders ${x} = product while the literal 7*7 is consumed
    # by #set, so ssti_evaluated should flag it.
    rendered = "result: 49"  # product present, raw expr absent
    assert ssti_evaluated("49", "7*7", rendered) is True
    # A non-evaluating engine echoes the payload verbatim -> not flagged.
    assert ssti_evaluated("49", "7*7", "result: #set($x=7*7)${x}") is False


# ----------------------------------------------------------------------- SSRF
def test_ssrf_metadata_covers_multiple_clouds() -> None:
    blob = "\n".join(SSRF_METADATA)
    assert "169.254.169.254" in blob  # AWS / Azure link-local
    assert "metadata.google.internal" in blob  # GCP
    assert "100.100.100.200" in blob  # Alibaba Cloud
    assert "2852039166" in blob  # decimal IP-obfuscation bypass
    assert len(SSRF_METADATA) >= 8


def test_ssrf_no_payload_url_self_triggers_detector() -> None:
    # The detector matches signatures present only in genuine metadata responses.
    # If a payload URL contained one, a reflected payload would false-positive.
    for url in SSRF_METADATA:
        assert detect_metadata_leak(url) is False, url


def test_ssrf_detector_matches_each_cloud_response_signature() -> None:
    assert detect_metadata_leak('{"accountId":"1","instance-id":"i-0abc"}')  # AWS
    assert detect_metadata_leak('{"azEnvironment":"AzurePublicCloud","vmId":"x"}')  # Azure
    assert detect_metadata_leak('{"access_token":"ya29.a0Af","expires_in":3599}')  # GCP
    assert detect_metadata_leak('{"droplet_id":123,"hostname":"web1"}')  # DigitalOcean
    assert detect_metadata_leak('{"ociAdName":"ad1","canonicalRegionName":"us"}')  # Oracle
    assert detect_metadata_leak("a perfectly ordinary web page") is False


# ------------------------------------------------------------------------ XSS
def test_xss_execution_payloads_all_carry_marker_global() -> None:
    marker = "M4rk"
    payloads = xss_execution_payloads(marker)
    assert payloads
    # The browser-confirm contract: every payload sets window['__hx_<marker>'].
    assert all(f"__hx_{marker}" in p for p in payloads)
    blob = "\n".join(payloads)
    assert "<script>" in blob
    assert "onerror" in blob
    assert "onload" in blob


def test_xss_payloads_include_context_spanning_polyglot() -> None:
    marker = "M4rk"
    payloads = xss_execution_payloads(marker)
    # The polyglot breaks out of several contexts in one string; identify it by
    # its multi-context breakout markers.
    assert any("</scRipt" in p and "oNloAd" in p for p in payloads)
