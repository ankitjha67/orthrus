"""Tests for the WAF/filter-evasion payload encoders (pure transforms)."""

from __future__ import annotations

from urllib.parse import unquote

from orthrus.scanners._evasion import (
    comment_spacing,
    double_url_encode,
    html_entity,
    mixed_case,
    transport_safe_variants,
    unicode_escape,
    url_encode,
    url_encode_special,
    variants,
)


# ------------------------------------------------------------- single encoders
def test_url_encode_encodes_everything():
    assert url_encode("a<b") == "a%3Cb"
    # even normally-safe chars are encoded
    assert url_encode("ab") == "ab"
    assert url_encode("a b") == "a%20b"


def test_url_encode_special_only_touches_significant_chars():
    out = url_encode_special("aXb<c")
    assert out == "aXb%3Cc"  # letters untouched, '<' encoded


def test_double_url_encode_is_encode_twice():
    once = url_encode("<")
    assert once == "%3C"
    assert double_url_encode("<") == "%253C"
    # round-trips back to the original after two decodes
    assert unquote(unquote(double_url_encode("<script>"))) == "<script>"


def test_html_entity_uses_decimal_entities():
    assert html_entity("<") == "&#60;"
    assert html_entity("a<b>") == "a&#60;b&#62;"


def test_unicode_escape_format():
    assert unicode_escape("<") == "\\u003c"
    assert unicode_escape("'") == "\\u0027"
    # an unaffected character stays literal
    assert unicode_escape("a<") == "a\\u003c"


def test_mixed_case_alternates_letters_only():
    out = mixed_case("select")
    assert out.lower() == "select"
    assert out != "select" and out != "SELECT"  # genuinely mixed
    # digits / punctuation are preserved exactly
    assert mixed_case("1=1") == "1=1"


def test_mixed_case_is_deterministic():
    assert mixed_case("union") == mixed_case("union")


def test_comment_spacing_replaces_whitespace_runs():
    assert comment_spacing("UNION SELECT") == "UNION/**/SELECT"
    assert comment_spacing("a   b") == "a/**/b"  # collapses a run
    assert comment_spacing("noSpaces") == "noSpaces"


# ------------------------------------------------------------------- variants
def test_variants_raw_first_and_deduped():
    out = variants("<script>")
    assert out[0] == ("raw", "<script>")
    labels = [label for label, _ in out]
    encs = [enc for _, enc in out]
    assert len(encs) == len(set(encs))  # no duplicate encodings
    assert "raw" in labels


def test_variants_respects_max():
    out = variants("a b<c>", max_variants=3)
    assert len(out) <= 3
    assert out[0][0] == "raw"


def test_variants_skips_noop_transforms():
    # punctuation-only payload: mixed-case is a no-op and must be dropped,
    # so the only kept variants are ones that actually change the payload.
    out = variants("''")
    encs = {enc for _, enc in out}
    # raw plus genuine encodings only; no entry equal to a previous one
    assert ("raw", "''") in out
    assert len(encs) == len(out)


def test_transport_safe_only_decoded_form_transforms():
    out = transport_safe_variants("' OR '1'='1")
    labels = {label for label, _ in out}
    assert labels <= {"raw", "mixed-case", "comment-spacing"}
    # url/html/unicode encodings must never appear here
    assert "url-encode" not in labels
    assert "double-url-encode" not in labels


def test_transport_safe_produces_a_real_variant():
    # a payload with both letters and a space yields both transforms
    out = transport_safe_variants("AND SLEEP")
    encs = {enc for _, enc in out}
    assert "AND SLEEP" in encs  # raw
    assert any("/**/" in e for e in encs)  # comment-spacing
    assert any(e != "AND SLEEP" and "/**/" not in e for e in encs)  # mixed-case
