"""The --fail-on severity gate: maps a scan's severity tally to a CI exit code
so a pipeline can fail the build when vulnerabilities at/above a threshold exist."""

from __future__ import annotations

import pytest

from orthrus.main import FAIL_ON_EXIT_CODE, _apply_fail_on, _gate_breached


# ------------------------------------------------------------- gate predicate
def test_gate_trips_at_or_above_threshold():
    counts = {"high": 2, "low": 5}
    assert _gate_breached(counts, "high") is True  # exact match trips
    assert _gate_breached(counts, "medium") is True  # high is above medium
    assert _gate_breached(counts, "critical") is False  # nothing that severe


def test_gate_ignores_empty_buckets():
    # A bucket present with a zero count must not trip the gate.
    assert _gate_breached({"critical": 0, "high": 0}, "high") is False
    assert _gate_breached({}, "info") is False


def test_gate_info_threshold_trips_on_anything():
    assert _gate_breached({"info": 1}, "info") is True
    assert _gate_breached({"low": 1}, "info") is True


def test_gate_threshold_is_case_insensitive():
    assert _gate_breached({"high": 1}, "HIGH") is True


# ------------------------------------------------------------ exit behaviour
def test_apply_fail_on_noop_when_disabled():
    # No threshold => never exits, even with critical findings present.
    _apply_fail_on({"critical": 9}, None)


def test_apply_fail_on_noop_when_below_threshold():
    _apply_fail_on({"low": 3}, "high")  # nothing high+ => returns cleanly


def test_apply_fail_on_exits_with_dedicated_code():
    with pytest.raises(SystemExit) as exc:
        _apply_fail_on({"high": 1}, "high")
    assert exc.value.code == FAIL_ON_EXIT_CODE
    assert FAIL_ON_EXIT_CODE != 2  # distinct from Click's usage-error code
