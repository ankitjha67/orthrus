"""Tests for the SSTI evaluation detector."""

from __future__ import annotations

from hydra.scanners.ssti import ssti_evaluated


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
