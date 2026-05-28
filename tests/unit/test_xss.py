"""Tests for the pure reflected-XSS reflection detector/classifier."""

from __future__ import annotations

import html

from hydra.core.schemas import Confidence, Severity
from hydra.scanners.xss import build_payload, classify, detect_reflection


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
