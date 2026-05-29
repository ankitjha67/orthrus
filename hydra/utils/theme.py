"""Terminal design system for HYDRA's CLI — the single 'token layer' for output.

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
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

ACCENT = "red3"

# Named styles registered on the shared Console. Reference them by name in
# Rich markup ("[sev.high]...[/]") or via the helpers below.
HYDRA_THEME = Theme(
    {
        "hydra.accent": "bold red3",
        "hydra.muted": "grey50",
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
    "██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗\n"
    "██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗\n"
    "███████║ ╚████╔╝ ██║  ██║██████╔╝███████║\n"
    "██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║\n"
    "██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║\n"
    "╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝"
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
    "tentative": "hydra.muted",
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
    table = Table(title="[hydra.accent]FINDINGS[/]", border_style="hydra.muted", expand=False)
    table.add_column("Sev", no_wrap=True)
    table.add_column("Type", style="bold", no_wrap=True)
    table.add_column("Finding")
    table.add_column("URL", style="hydra.muted", overflow="fold")
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
    """Print the HYDRA startup banner (accent-styled) to ``console``."""
    art = _BANNER_ART if _unicode_ok(console) else "H Y D R A"
    console.print(Text(art, style="hydra.accent"))
    console.print(Text(f" {_SUBTITLE} · v{version}", style="hydra.muted"))
    console.print(Text(f" {_NOTICE}", style="hydra.accent"))
    console.print()


def section(console: Console, title: str) -> None:
    """Print a left-aligned accent rule marking a new phase/section."""
    console.print(Rule(Text(title, style="hydra.accent"), style="hydra.accent", align="left"))


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
        body.append(label, style="hydra.muted")
        body.append(f"{_fmt(value)}\n")
    body.rstrip()
    return Panel(
        body,
        title="[hydra.accent]AUTHORIZED SCOPE[/]",
        border_style="hydra.accent",
        expand=False,
    )


__all__ = [
    "ACCENT",
    "HYDRA_THEME",
    "confidence_style",
    "findings_table",
    "render_banner",
    "scope_panel",
    "section",
    "severity_style",
    "status_style",
]
