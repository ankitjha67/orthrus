#!/usr/bin/env python3
"""Render an Orthrus scan report as the tool's themed terminal UI.

Loads a JSON report (the ``orthrus scan --format json`` output) and renders the
banner, the AUTHORIZED SCOPE panel, the scan summary, OWASP Top-10 coverage and
the colour-coded findings table into a recording :class:`rich.console.Console`,
then exports an **SVG** and **HTML** frame you can open in a browser — handy for
docs, slides, and sharing results. A **PNG** is written too when Playwright +
Chromium are available (``pip install orthrus-framework[browser]``).

Usage
-----
    python examples/render_report_ui.py [REPORT_JSON] [-o OUT_BASE]
                                        [--width N] [--max-findings N] [--no-png]

With no arguments it renders the bundled ``examples/sample_report.json`` (a real
run against the in-repo, 127.0.0.1-only practice target) to ``examples/sample_report.{svg,html}``.
"""

from __future__ import annotations

import argparse
import io
import json
import types
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from orthrus.utils import theme

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def build_console(data: dict, *, width: int, max_findings: int | None) -> Console:
    """Render a full report dict into a recording, exportable Console."""
    scan = data["scan"]
    scope = scan.get("scope", {})
    summary = data["summary"]
    findings = [types.SimpleNamespace(**f) for f in data["findings"]]
    if max_findings is not None:
        findings = findings[:max_findings]

    # Route live output to an in-memory buffer so block-art glyphs never hit a
    # legacy/cp1252 stdout; only the UTF-8 record buffer feeds the SVG/HTML.
    console = Console(
        record=True,
        force_terminal=True,
        width=width,
        theme=theme.ORTHRUS_THEME,
        file=io.StringIO(),
    )
    # The export buffer is always UTF-8, so render the full block-art banner
    # regardless of how the host terminal's encoding is detected.
    def _always_unicode(_console: Console) -> bool:
        return True

    theme._unicode_ok = _always_unicode

    theme.render_banner(console, data.get("branding", {}).get("version", "0.1.0"))
    console.print(
        theme.scope_panel(
            domains=scope.get("domains"),
            ip_ranges=scope.get("ip_ranges"),
            ports=scope.get("ports"),
            exclude=scope.get("exclude_paths"),
        )
    )
    console.print()

    theme.section(console, "SCAN · SUMMARY")
    counts = summary.get("counts", {})
    tally = Table.grid(padding=(0, 2))
    tally.add_column(justify="right")
    tally.add_column()
    tally.add_row("target", Text(str(scan.get("target", "")), style="orthrus.muted"))
    tally.add_row("scan id", Text(str(scan.get("id", "")), style="orthrus.muted"))
    tally.add_row("findings", Text(str(summary.get("total", len(findings))), style="bold"))
    tally.add_row("confirmed", Text(str(summary.get("confirmed", 0)), style="status.completed"))
    sev_line = Text()
    for name in _SEVERITY_ORDER:
        sev_line.append(f" {counts.get(name, 0)} {name.upper()} ", style=theme.severity_style(name))
        sev_line.append("  ")
    tally.add_row("severity", sev_line)
    console.print(tally)
    console.print()

    owasp_counts = summary.get("owasp_counts")
    if owasp_counts:
        theme.section(console, "SCAN · OWASP TOP 10 COVERAGE")
        owasp = Table.grid(padding=(0, 2))
        owasp.add_column(style="orthrus.muted")
        owasp.add_column(justify="right", style="bold")
        for cat, n in sorted(owasp_counts.items(), key=lambda kv: -kv[1]):
            owasp.add_row(cat, str(n))
        console.print(owasp)
        console.print()

    theme.section(console, "SCAN · FINDINGS")
    console.print(theme.findings_table(findings))
    console.print()
    console.print(
        Text(
            " authorized security testing only — render of an Orthrus JSON report",
            style="orthrus.accent",
        )
    )
    return console


def _write_png(html_path: Path, png_path: Path, width: int) -> bool:
    """Rasterise the HTML frame to PNG via Playwright; returns False if unavailable."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(
                viewport={"width": width, "height": 900}, device_scale_factor=2
            )
            page.goto(html_path.resolve().as_uri())
            page.screenshot(path=str(png_path), full_page=True)
            browser.close()
    except Exception as exc:  # PNG is best-effort, never fatal
        print(f"  (PNG skipped: {exc})")
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    here = Path(__file__).resolve().parent
    parser.add_argument(
        "report",
        nargs="?",
        type=Path,
        default=here / "sample_report.json",
        help="Path to an orthrus JSON report (default: examples/sample_report.json)",
    )
    parser.add_argument(
        "-o",
        "--out-base",
        type=Path,
        default=None,
        help="Output path stem (default: alongside the report). Extensions are appended.",
    )
    parser.add_argument("--width", type=int, default=118, help="Render width in columns")
    parser.add_argument(
        "--max-findings",
        type=int,
        default=None,
        help="Cap the findings table to N rows (useful for compact doc screenshots)",
    )
    parser.add_argument("--no-png", action="store_true", help="Skip the PNG rasterisation")
    args = parser.parse_args(argv)

    data = json.loads(args.report.read_text(encoding="utf-8"))
    console = build_console(data, width=args.width, max_findings=args.max_findings)

    out_base = args.out_base or args.report.with_suffix("")
    out_base.parent.mkdir(parents=True, exist_ok=True)
    svg_path = out_base.with_suffix(".svg")
    html_path = out_base.with_suffix(".html")
    png_path = out_base.with_suffix(".png")

    console.save_svg(svg_path, title="Orthrus — scan report", clear=False)
    console.save_html(html_path)
    print(f"wrote {svg_path}  ({svg_path.stat().st_size:,} bytes)")
    print(f"wrote {html_path} ({html_path.stat().st_size:,} bytes)")

    if not args.no_png and _write_png(html_path, png_path, args.width * 9):
        print(f"wrote {png_path}  ({png_path.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
