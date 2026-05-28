"""Tests for the IDOR enumeration signal."""

from __future__ import annotations

from hydra.scanners.idor import idor_signal

ORIGINAL = "User profile: Alice, alice@example.com, member since 2020 " + "x" * 80
NEIGHBOR = "User profile: Bob, bob@example.com, member since 2021 " + "y" * 80


def test_distinct_similar_object_signals_idor():
    assert idor_signal(ORIGINAL, NEIGHBOR, 200) is True


def test_non_200_neighbor_is_negative():
    assert idor_signal(ORIGINAL, NEIGHBOR, 404) is False


def test_identical_content_is_negative():
    assert idor_signal(ORIGINAL, ORIGINAL, 200) is False


def test_short_neighbor_is_negative():
    assert idor_signal(ORIGINAL, "Not found", 200) is False
