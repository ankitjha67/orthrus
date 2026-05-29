"""Terminal design system for ORTHRUS's CLI — the single 'token layer' for output.

One place owns the palette, severity/status styling, the startup banner, and the
section/scope chrome, so every command renders with one consistent look instead
of ad-hoc inline styles scattered across modules. All of this targets the shared
stderr Console (stdout stays reserved for machine-readable report data), and
Rich downgrades colour/glyphs automatically when output is piped or the terminal
is limited — so CI logs stay clean.

Accent is crimson: an offensive-security "attack" identity. Severity colours
stay conventional (critical=red, high=bright-red, medium=yellow, low=cyan,
info=dim) so an operator can read risk at a glance.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

ACCENT = "red3"

# Named styles registered on the shared Console. Reference them by name in
# Rich markup ("[sev.high]...[/]") or via the helpers below.
ORTHRUS_THEME = Theme(
    {
        "orthrus.accent": "bold red3",
        "orthrus.muted": "grey50",
        # Severity — conventional risk colours.
        "sev.critical": "bold white on red3",
        "sev.high": "bold bright_red",
        "sev.medium": "bold yellow",
        "sev.low": "cyan",
        "sev.info": "dim",
        # Scan lifecycle status.
        "status.completed": "bold green",
        "status.running": "bold yellow",
        "status.failed": "bold red",
        "status.pending": "dim",
        # Scanner outcome.
        "status.ok": "green",
        "status.crash": "bold red",
    }
)

# ANSI-Shadow block logo. Rendered only when the terminal can encode the
# box-drawing glyphs; otherwise render_banner() falls back to plain text.
_BANNER_ART = (
    " ██████╗ ██████╗ ████████╗██╗  ██╗██████╗ ██╗   ██╗███████╗\n"
    "██╔═══██╗██╔══██╗╚══██╔══╝██║  ██║██╔══██╗██║   ██║██╔════╝\n"
    "██║   ██║██████╔╝   ██║   ███████║██████╔╝██║   ██║███████╗\n"
    "██║   ██║██╔══██╗   ██║   ██╔══██║██╔══██╗██║   ██║╚════██║\n"
    "╚██████╔╝██║  ██║   ██║   ██║  ██║██║  ██║╚██████╔╝███████║\n"
    " ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝"
)

_SUBTITLE = "automated vulnerability discovery"
_NOTICE = "authorized security testing only"

_SEVERITIES = ("critical", "high", "medium", "low", "info")
_STATUSES = ("completed", "running", "failed", "pending")
# Highest risk first, so findings_table() can sort the operator's triage list.
_SEVERITY_RANK = {name: i for i, name in enumerate(_SEVERITIES)}

# Confidence -> theme token. Confirmed (exploitation proved it) reads green;
# tentative is muted so the eye lands on what's been verified.
_CONFIDENCE_STYLES = {
    "confirmed": "status.completed",
    "firm": "default",
    "tentative": "orthrus.muted",
}


def _unicode_ok(console: Console) -> bool:
    """True when the console can render the block-art glyphs."""
    return "utf" in (console.encoding or "").lower() and not console.legacy_windows


def severity_style(severity: str) -> str:
    """Theme style name for a severity, or 'default' for unknown values."""
    return f"sev.{severity.lower()}" if severity.lower() in _SEVERITIES else "default"


def status_style(status: str) -> str:
    """Theme style name for a scan status, or 'default' for unknown values."""
    return f"status.{status.lower()}" if status.lower() in _STATUSES else "default"


def confidence_style(confidence: str) -> str:
    """Theme style name for a finding's confidence, or 'default' for unknowns."""
    return _CONFIDENCE_STYLES.get(str(confidence).lower(), "default")


def findings_table(findings: object) -> Table:
    """A color-coded, severity-sorted table of individual findings.

    Complements the severity tally: the tally answers "how many of each", this
    answers "what fired, where, how bad, and how sure are we" — the list an
    operator actually triages. Accepts any objects exposing ``severity``,
    ``vuln_type``, ``title``, ``url`` and ``confidence`` (duck-typed so the
    helper stays decoupled from the schemas layer).
    """
    table = Table(title="[orthrus.accent]FINDINGS[/]", border_style="orthrus.muted", expand=False)
    table.add_column("Sev", no_wrap=True)
    table.add_column("Type", style="bold", no_wrap=True)
    table.add_column("Finding")
    table.add_column("URL", style="orthrus.muted", overflow="fold")
    table.add_column("Conf", no_wrap=True)

    ordered = sorted(
        findings,  # type: ignore[call-overload]
        key=lambda f: (_SEVERITY_RANK.get(str(f.severity).lower(), 99), str(f.vuln_type)),
    )
    for f in ordered:
        sev = str(f.severity)
        table.add_row(
            Text(sev.upper(), style=severity_style(sev)),
            str(f.vuln_type),
            str(getattr(f, "title", "") or ""),
            str(f.url),
            Text(str(f.confidence), style=confidence_style(f.confidence)),
        )
    return table


def render_banner(console: Console, version: str) -> None:
    """Print the ORTHRUS startup banner (accent-styled) to ``console``."""
    art = _BANNER_ART if _unicode_ok(console) else "O R T H R U S"
    console.print(Text(art, style="orthrus.accent"))
    console.print(Text(f" {_SUBTITLE} · v{version}", style="orthrus.muted"))
    console.print(Text(f" {_NOTICE}", style="orthrus.accent"))
    console.print()


def section(console: Console, title: str) -> None:
    """Print a left-aligned accent rule marking a new phase/section."""
    console.print(Rule(Text(title, style="orthrus.accent"), style="orthrus.accent", align="left"))


def make_progress(console: Console) -> Progress:
    """A themed, transient progress bar for phase work (recon/scan).

    Replaces the stream of per-module log lines with one live bar that shows the
    current module, completion count and elapsed time. ``transient=True`` leaves
    no scrollback once the phase finishes. Callers should gate on
    ``console.is_terminal`` (and not --quiet) so piped output / CI keeps the
    plain log-line path instead of a half-rendered bar.
    """
    return Progress(
        SpinnerColumn(style="orthrus.accent"),
        TextColumn("[orthrus.muted]{task.description}"),
        BarColumn(complete_style="orthrus.accent", finished_style="status.completed"),
        TextColumn("[orthrus.muted]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


def _fmt(value: object) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value) if value else "(none)"
    return str(value) if value not in (None, "") else "(none)"


def scope_panel(
    *,
    domains: object = None,
    ip_ranges: object = None,
    ports: object = None,
    exclude: object = None,
) -> Panel:
    """A prominent panel for the authorized engagement boundary.

    Scope enforcement is load-bearing, so it gets a bordered panel (not a log
    line) the operator can confirm before any request goes out.
    """
    body = Text()
    for label, value in (
        ("domains   ", domains),
        ("ip ranges ", ip_ranges),
        ("ports     ", ports if ports else "any"),
        ("exclude   ", exclude),
    ):
        body.append(label, style="orthrus.muted")
        body.append(f"{_fmt(value)}\n")
    body.rstrip()
    return Panel(
        body,
        title="[orthrus.accent]AUTHORIZED SCOPE[/]",
        border_style="orthrus.accent",
        expand=False,
    )


__all__ = [
    "ACCENT",
    "ORTHRUS_THEME",
    "confidence_style",
    "findings_table",
    "make_progress",
    "render_banner",
    "scope_panel",
    "section",
    "severity_style",
    "status_style",
]
