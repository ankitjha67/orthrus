"""Tests for the SSTI evaluation detector."""

from __future__ import annotations

from orthrus.scanners._payloads import ssti_templates
from orthrus.scanners.ssti import ssti_evaluated


def test_templates_cover_distinct_evaluating_engines():
    labels = {label for label, _ in ssti_templates("7*11")}
    # The core delimiter families plus the newly-added distinct evaluators.
    assert {"Jinja2/Twig", "ERB/EJS", "Velocity", "Latte", "Smarty-math"} <= labels


def test_templates_embed_the_expression():
    # Every payload must contain the arithmetic expression so the detector can
    # match its evaluated product (and never false-positive on verbatim echo).
    assert all("7*11" in payload for _label, payload in ssti_templates("7*11"))


def test_latte_and_smarty_have_distinct_syntax():
    payloads = dict((label, p) for label, p in ssti_templates("7*11"))
    assert payloads["Latte"] == "{=7*11}"
    assert payloads["Smarty-math"] == "{7*11}"


def test_evaluated_product_present_expression_absent():
    body = "<p>result: 1787569</p>"
    assert ssti_evaluated("1787569", "1337*1337", body) is True


def test_raw_expression_reflected_is_not_evaluated():
    body = "<p>result: 1337*1337</p>"
    assert ssti_evaluated("1787569", "1337*1337", body) is False


def test_both_present_counts_as_reflection():
    body = "echo 1337*1337 -> 1787569"
    assert ssti_evaluated("1787569", "1337*1337", body) is False


def test_neither_present():
    assert ssti_evaluated("1787569", "1337*1337", "nothing here") is False
