"""Tests for the pure CORS analyzer."""

from __future__ import annotations

from orthrus.core.schemas import Severity
from orthrus.scanners.cors import analyze_cors

URL = "https://api.target.com/data"
EVIL = "https://orthrus-arbitrary.example"


def test_no_acao_is_clean():
    assert analyze_cors(URL, EVIL, {}) is None


def test_reflected_arbitrary_origin_medium():
    f = analyze_cors(URL, EVIL, {"Access-Control-Allow-Origin": EVIL})
    assert f is not None
    assert f.severity == Severity.MEDIUM


def test_reflected_origin_with_credentials_high():
    headers = {
        "Access-Control-Allow-Origin": EVIL,
        "Access-Control-Allow-Credentials": "true",
    }
    f = analyze_cors(URL, EVIL, headers)
    assert f is not None
    assert f.severity == Severity.HIGH


def test_null_origin_trust():
    f = analyze_cors(URL, "null", {"Access-Control-Allow-Origin": "null"})
    assert f is not None
    assert "null" in f.title.lower()


def test_trusted_specific_origin_is_clean():
    headers = {"Access-Control-Allow-Origin": "https://trusted.target.com"}
    assert analyze_cors(URL, EVIL, headers) is None


def test_wildcard_without_credentials_is_clean():
    assert analyze_cors(URL, EVIL, {"Access-Control-Allow-Origin": "*"}) is None


def test_wildcard_with_credentials_high():
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }
    f = analyze_cors(URL, EVIL, headers)
    assert f is not None
    assert f.severity == Severity.HIGH
