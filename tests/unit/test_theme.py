"""The terminal design system: palette tokens, severity/status style mapping,
the startup banner (+ ASCII fallback), section rules, and the scope panel."""

from __future__ import annotations

import io
from dataclasses import dataclass

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich.table import Table

from hydra.utils import theme


def _render(renderable_or_fn, width: int = 80) -> str:
    # force_terminal=False strips ANSI colour so we can assert on plain text.
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=width, theme=theme.HYDRA_THEME)
    renderable_or_fn(console)
    return buf.getvalue()


# ------------------------------------------------------------------ tokens
def test_theme_defines_core_styles():
    names = set(theme.HYDRA_THEME.styles)
    assert {"hydra.accent", "sev.critical", "sev.high", "status.failed"} <= names


def test_severity_style_maps_known_and_unknown():
    assert theme.severity_style("CRITICAL") == "sev.critical"
    assert theme.severity_style("low") == "sev.low"
    assert theme.severity_style("bogus") == "default"


def test_status_style_maps_known_and_unknown():
    assert theme.status_style("completed") == "status.completed"
    assert theme.status_style("Failed") == "status.failed"
    assert theme.status_style("???") == "default"


# ------------------------------------------------------------------ banner
def test_render_banner_includes_version_and_notice():
    out = _render(lambda c: theme.render_banner(c, "9.9.9"))
    assert "v9.9.9" in out
    assert "authorized security testing only" in out


def test_render_banner_falls_back_to_ascii(monkeypatch):
    # Terminals that can't encode the block glyphs get a plain-text wordmark.
    monkeypatch.setattr(theme, "_unicode_ok", lambda _console: False)
    out = _render(lambda c: theme.render_banner(c, "1.0"))
    assert "H Y D R A" in out


# ----------------------------------------------------------- section / scope
def test_section_renders_title():
    out = _render(lambda c: theme.section(c, "PHASE · SCAN"))
    assert "PHASE" in out and "SCAN" in out


def test_scope_panel_is_a_panel_and_shows_boundary():
    panel = theme.scope_panel(
        domains=["example.com"], ip_ranges=[], ports=[80, 443], exclude=["/logout"]
    )
    assert isinstance(panel, Panel)
    out = _render(lambda c: c.print(panel))
    assert "AUTHORIZED SCOPE" in out
    assert "example.com" in out
    assert "/logout" in out


def test_scope_panel_empty_fields_render_placeholders():
    out = _render(lambda c: c.print(theme.scope_panel()))
    assert "(none)" in out
    assert "any" in out  # ports default


# ---------------------------------------------------------------- findings
@dataclass
class _Finding:
    severity: str
    vuln_type: str
    title: str
    url: str
    confidence: str


def test_confidence_style_maps_known_and_unknown():
    assert theme.confidence_style("confirmed") == "status.completed"
    assert theme.confidence_style("TENTATIVE") == "hydra.muted"
    assert theme.confidence_style("???") == "default"


def test_findings_table_is_a_table_and_shows_rows():
    findings = [
        _Finding("low", "security-headers", "Missing CSP", "https://ex.com/", "firm"),
        _Finding("critical", "sqli", "SQL injection", "https://ex.com/login", "confirmed"),
    ]
    table = theme.findings_table(findings)
    assert isinstance(table, Table)
    out = _render(lambda c: c.print(table), width=120)
    assert "FINDINGS" in out
    assert "sqli" in out
    assert "security-headers" in out
    assert "https://ex.com/login" in out


def test_findings_table_sorts_by_severity_descending():
    findings = [
        _Finding("info", "info-leak", "Info", "https://ex.com/a", "tentative"),
        _Finding("critical", "rce", "RCE", "https://ex.com/b", "confirmed"),
        _Finding("medium", "xss", "XSS", "https://ex.com/c", "firm"),
    ]
    out = _render(lambda c: c.print(theme.findings_table(findings)))
    # Highest severity must render first (its row appears earliest in the output).
    assert out.index("rce") < out.index("xss") < out.index("info-leak")


def test_findings_table_handles_empty():
    out = _render(lambda c: c.print(theme.findings_table([])))
    assert "FINDINGS" in out


# ---------------------------------------------------------------- progress
def test_make_progress_returns_progress_and_renders():
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True, width=80, theme=theme.HYDRA_THEME)
    progress = theme.make_progress(console)
    assert isinstance(progress, Progress)
    # Drive a short lifecycle to confirm it renders without raising.
    with progress:
        task = progress.add_task("scan · sqli", total=2)
        progress.advance(task)
        progress.advance(task)
