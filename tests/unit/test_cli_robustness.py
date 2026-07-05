"""CLI robustness: tolerate URL-shaped --scope tokens and unsafe -o paths."""

from __future__ import annotations

import os
import sys

from orthrus.main import _ensure_utf8_output, _install_uvloop, build_scope
from orthrus.reporting.generator import _safe_output_path
from orthrus.utils.scope import ScopeValidator


def test_install_uvloop_is_safe() -> None:
    # No-op on Windows / when uvloop is absent; must never raise either way.
    _install_uvloop()


# ----------------------------------------------------------------- utf-8 output
class _RecordingStream:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def reconfigure(self, **kw) -> None:
        self.calls.append(kw)


def test_ensure_utf8_output_forces_utf8_with_replace(monkeypatch) -> None:
    # Windows consoles default to cp1252; the runbook/summary emit emoji (🔓) and →,
    # which raise UnicodeEncodeError on a piped cp1252 stdout. The CLI must force UTF-8.
    out, err = _RecordingStream(), _RecordingStream()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    _ensure_utf8_output()
    assert out.calls == [{"encoding": "utf-8", "errors": "replace"}]
    assert err.calls == [{"encoding": "utf-8", "errors": "replace"}]


def test_ensure_utf8_output_tolerates_streams_without_reconfigure(monkeypatch) -> None:
    # A stream that can't be reconfigured (or is already detached) must never crash.
    monkeypatch.setattr(sys, "stdout", object())
    monkeypatch.setattr(sys, "stderr", object())
    _ensure_utf8_output()  # no AttributeError


# ----------------------------------------------------------------- scope
def test_scope_normalizes_url_and_port_tokens() -> None:
    scope = build_scope(
        "https://pentest-ground.com:4280,*.https://pentest-ground.com:4280",
        "https://pentest-ground.com:4280",
        None,
    )
    assert "pentest-ground.com" in scope.domains
    assert "*.pentest-ground.com" in scope.domains
    assert 4280 in scope.ports
    # The (previously broken) URL token now actually matches the live host:
    assert ScopeValidator(scope).is_allowed("https://pentest-ground.com:4280/app") is True


def test_scope_plain_domain_unchanged() -> None:
    scope = build_scope("pentest-ground.com", "https://pentest-ground.com:9000", None)
    assert scope.domains == ["pentest-ground.com"]
    assert ScopeValidator(scope).is_allowed("https://pentest-ground.com:9000/") is True


# ----------------------------------------------------------------- output path
def test_safe_output_path_sanitizes_colon() -> None:
    out = _safe_output_path("reports/pentest-ground.com:5013.html")
    base = os.path.basename(out)
    assert ":" not in base  # would have been an NTFS alternate-data-stream on Windows
    assert base == "pentest-ground.com-5013.html"


def test_safe_output_path_strips_pasted_url_scheme() -> None:
    out = _safe_output_path("reports/https://pentest-ground.com:4280.html")
    base = os.path.basename(out)
    assert "://" not in out and ":" not in base
    assert base == "pentest-ground.com-4280.html"


def test_safe_output_path_leaves_clean_paths_alone() -> None:
    assert _safe_output_path("reports/demo.json") == os.path.join("reports", "demo.json")
    assert _safe_output_path("report.html") == "report.html"
