"""Detection-accuracy scorer (pure matching of findings against ground truth)."""

from __future__ import annotations

import json

import pytest

from hydra.benchmark.runner import load_truth
from hydra.benchmark.scorer import BenchmarkReport, Expected, match, score
from hydra.core.schemas import Finding, Severity


def _finding(vuln_type: str, url: str, parameter: str | None = None) -> Finding:
    return Finding(
        vuln_type=vuln_type,
        title=f"{vuln_type} at {url}",
        severity=Severity.HIGH,
        url=url,
        parameter=parameter,
    )


# ------------------------------------------------------------------- match()
def test_match_requires_same_vuln_type_case_insensitive():
    f = _finding("XSS", "http://h/search?q=1", "q")
    assert match(f, Expected(vuln_type="xss", url_contains="/search")) is True
    assert match(f, Expected(vuln_type="sqli", url_contains="/search")) is False


def test_match_url_substring():
    f = _finding("sqli", "http://h/sqli?id=1", "id")
    assert match(f, Expected(vuln_type="sqli", url_contains="/sqli")) is True
    assert match(f, Expected(vuln_type="sqli", url_contains="/other")) is False


def test_match_empty_url_contains_matches_any_url():
    f = _finding("security-headers", "http://h/anything")
    assert match(f, Expected(vuln_type="security-headers", url_contains="")) is True


def test_match_param_when_specified():
    f = _finding("idor", "http://h/api/users/2", "id")
    assert match(f, Expected(vuln_type="idor", url_contains="/api/users", param="id")) is True
    assert match(f, Expected(vuln_type="idor", url_contains="/api/users", param="uid")) is False


def test_match_param_absent_on_finding_fails_when_expected():
    f = _finding("idor", "http://h/api/users/2", parameter=None)
    assert match(f, Expected(vuln_type="idor", param="id")) is False


# ------------------------------------------------------------------- score()
def test_score_detects_and_misses():
    findings = [
        _finding("xss", "http://h/search?q=1", "q"),
        _finding("sqli", "http://h/sqli?id=1", "id"),
    ]
    expected = [
        Expected("xss", "/search", "q"),
        Expected("sqli", "/sqli", "id"),
        Expected("lfi", "/download", "file"),  # not found
    ]
    report = score(findings, expected)
    assert {e.vuln_type for e in report.detected} == {"xss", "sqli"}
    assert {e.vuln_type for e in report.missed} == {"lfi"}
    assert report.detection_rate == pytest.approx(2 / 3)


def test_score_unexpected_finding_is_false_positive():
    findings = [
        _finding("xss", "http://h/search?q=1", "q"),
        _finding("ssrf", "http://h/img?u=1", "u"),  # matches nothing
    ]
    expected = [Expected("xss", "/search", "q")]
    report = score(findings, expected)
    assert report.unexpected_count == 1
    assert report.unexpected[0].vuln_type == "ssrf"
    assert report.false_positive_rate == pytest.approx(0.5)


def test_score_optional_excluded_from_detection_rate():
    findings = [_finding("xss", "http://h/search?q=1", "q")]
    expected = [
        Expected("xss", "/search", "q"),
        Expected("xss", "/dom", optional=True),  # missed but optional
    ]
    report = score(findings, expected)
    assert report.detection_rate == pytest.approx(1.0)  # required-only
    assert report.required_total == 1
    assert report.optional_total == 1
    assert report.optional_detected == 0


def test_score_one_finding_satisfies_one_entry_no_double_count_as_fp():
    # A finding that matches an entry must not also be reported as unexpected.
    findings = [_finding("cors", "http://h/")]
    expected = [Expected("cors", "")]
    report = score(findings, expected)
    assert report.unexpected_count == 0
    assert report.detection_rate == pytest.approx(1.0)


def test_empty_findings_zero_detection():
    expected = [Expected("xss", "/search"), Expected("sqli", "/sqli")]
    report = score([], expected)
    assert report.detection_rate == pytest.approx(0.0)
    assert report.unexpected_count == 0


def test_report_rates_are_safe_when_nothing_to_score():
    report = BenchmarkReport()
    assert report.detection_rate == 1.0  # vacuously complete
    assert report.false_positive_rate == 0.0


# --------------------------------------------------------------- Expected I/O
def test_expected_from_dict_minimal_and_full():
    minimal = Expected.from_dict({"vuln_type": "xss"})
    assert minimal.vuln_type == "xss"
    assert minimal.url_contains == ""
    assert minimal.param is None
    assert minimal.optional is False

    full = Expected.from_dict(
        {"vuln_type": "idor", "url_contains": "/api/users", "param": "id", "optional": True}
    )
    assert full.param == "id"
    assert full.optional is True


def test_expected_from_dict_requires_vuln_type():
    with pytest.raises(ValueError):
        Expected.from_dict({"url_contains": "/x"})


# ------------------------------------------------------------- load_truth()
def test_load_bundled_reflecting_target_truth():
    name, expected = load_truth("reflecting-target")
    assert name == "reflecting-target"
    assert len(expected) > 10
    vuln_types = {e.vuln_type for e in expected}
    assert {"xss", "sqli", "ssti", "cmd-injection", "lfi", "ssrf"} <= vuln_types


def test_load_truth_from_path(tmp_path):
    p = tmp_path / "truth.json"
    p.write_text(json.dumps([{"vuln_type": "xss", "url_contains": "/x"}]), encoding="utf-8")
    name, expected = load_truth(str(p))
    assert name == "truth"
    assert expected[0].vuln_type == "xss"


def test_load_truth_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        load_truth("does-not-exist-anywhere")


def test_load_truth_empty_expected_raises(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text(json.dumps({"name": "x", "expected": []}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_truth(str(p))
