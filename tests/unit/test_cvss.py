"""Tests for the CVSS v3.1 base-score engine."""

from __future__ import annotations

import pytest

from hydra.core.schemas import Severity
from hydra.reporting.cvss import DEFAULT_VECTORS, base_score, severity_for_score


@pytest.mark.parametrize(
    "vector, expected",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),  # full network RCE
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),  # info disclosure
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),  # reflected XSS
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),  # IDOR
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),  # no impact -> 0
    ],
)
def test_base_score_known_vectors(vector, expected):
    assert base_score(vector) == expected


def test_severity_buckets():
    assert severity_for_score(0.0) == Severity.INFO
    assert severity_for_score(3.9) == Severity.LOW
    assert severity_for_score(6.9) == Severity.MEDIUM
    assert severity_for_score(8.9) == Severity.HIGH
    assert severity_for_score(9.8) == Severity.CRITICAL


def test_default_vectors_all_parse_to_a_score():
    for vuln_type, vector in DEFAULT_VECTORS.items():
        score = base_score(vector)
        assert 0.0 < score <= 10.0, f"{vuln_type} -> {score}"


def test_invalid_vector_is_zero():
    assert base_score("garbage") == 0.0
