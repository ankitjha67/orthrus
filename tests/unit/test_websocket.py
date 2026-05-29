"""Tests for the WebSocket origin-validation verdict."""

from __future__ import annotations

from orthrus.core.schemas import Severity
from orthrus.scanners.websocket import classify_ws


def test_foreign_origin_accepted_is_medium():
    assert classify_ws(True) == Severity.MEDIUM


def test_foreign_origin_rejected_is_clean():
    assert classify_ws(False) is None
