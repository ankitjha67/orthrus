"""Tests for the pure reflected-XSS reflection detector/classifier."""

from __future__ import annotations

import html

from hydra.core.schemas import Confidence, Severity
from hydra.scanners.stored_xss import _payload as stored_payload
from hydra.scanners.xss import (
    build_payload,
    classify,
    detect_reflection,
    execution_payloads,
    is_html_context,
)


def test_verbatim_reflection_detects_all_chars():
    marker = "hxssabc123"
    payload = build_payload(marker)
    body = f"<div>echo: {payload}</div>"
    reflected, survived = detect_reflection(marker, body)
    assert reflected is True
    assert survived == {"<", ">", '"', "'"}
    verdict = classify(survived)
    assert verdict is not None
    assert verdict[0] == Severity.HIGH
    assert verdict[1] == Confidence.FIRM


def test_html_encoded_reflection_has_no_surviving_chars():
    marker = "hxssdef456"
    payload = build_payload(marker)
    body = f"<div>echo: {html.escape(payload)}</div>"
    reflected, survived = detect_reflection(marker, body)
    assert reflected is True  # marker (alnum) still present
    assert survived == set()
    assert classify(survived) is None


def test_quote_only_breakout_is_medium_tentative():
    survived = {'"'}
    verdict = classify(survived)
    assert verdict is not None
    assert verdict[0] == Severity.MEDIUM
    assert verdict[1] == Confidence.TENTATIVE


def test_not_reflected():
    reflected, survived = detect_reflection("hxssZZZ", "<html>nothing here</html>")
    assert reflected is False
    assert survived == set()


def test_execution_payloads_use_marker_namespaced_global():
    # Guards the contract with BrowserManager.check_execution, which reads
    # window['__hx_<marker>']. A mismatch silently breaks browser confirmation.
    marker = "M0d3"
    payloads = execution_payloads(marker)
    assert payloads
    assert all(f"__hx_{marker}" in p for p in payloads)


def test_stored_payload_matches_global_contract():
    marker = "M0d3"
    assert f"__hx_{marker}" in stored_payload(marker)


def test_is_html_context_suppresses_json():
    # Reflecting markup into a JSON response is not XSS (not rendered as HTML).
    assert is_html_context("application/json") is False
    assert is_html_context("application/vnd.api+json; charset=utf-8") is False


def test_is_html_context_allows_html_and_sniffable():
    assert is_html_context("text/html; charset=utf-8") is True
    assert is_html_context("application/xhtml+xml") is True
    assert is_html_context("text/plain") is True  # sniffable
    assert is_html_context(None) is True  # missing type -> may be sniffed
    assert is_html_context("") is True
