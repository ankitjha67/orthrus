"""Canonical ORTHRUS visual palette — red / white / black, everywhere.

Single source of truth for colours in **every** HTML / report / UI surface: the
web dashboard, the attack-surface graph, the AI consultant report, and the Jinja
report templates. The CLI's crimson identity (``orthrus/utils/theme.py``, Rich
``red3``) is the anchor.

**Convention (applies to all current *and future* reports/UI):** use only these
tokens — red, white, black, and neutral greys (which are just shades of
black↔white). Do **not** introduce blue / green / teal / amber / purple. New
views, report formats, and upgrades must pull their colours from here.
"""

from __future__ import annotations

# Brand red — anchored to Rich `red3`.
RED = "#d70000"         # primary accent / brand (on dark)
RED_PRINT = "#c40000"   # slightly deeper, for ink-on-white (reports / PDF headers)
RED_BRIGHT = "#ff3b3b"  # high-emphasis / "hot"
RED_DARK = "#8b0000"    # deepest red (critical fill)
RED_LINK = "#ff5a5a"    # links on a dark background

WHITE = "#f0f0f0"       # primary text on dark
BLACK = "#0f0f0f"       # primary background (dark surfaces)
INK = "#1a1a1a"         # primary text on light (reports)

# Neutrals — shades of black↔white, so they stay on-palette.
GREY = "#a8a8a8"
GREY_DIM = "#6f6f6f"
LINE = "#2b2b2b"        # borders on dark
LINE_LIGHT = "#e2e2e2"  # borders on light
CODE_DARK_BG = "#141414"
PANEL = "#181818"

# Severity as a red-intensity ramp (hottest = critical) fading to grey for the
# low end. Two variants because contrast needs differ:
#   ON_DARK — coloured text on a black background (dashboard tables / graph).
#   FILL    — a filled pill/bar with white text (print reports).
SEVERITY_ON_DARK = {
    "critical": "#ff3b3b", "high": "#ff6b6b", "medium": "#ff9e9e",
    "low": "#c9c9c9", "info": "#8a8a8a",
}
SEVERITY_FILL = {
    "critical": "#8b0000", "high": "#b71c1c", "medium": "#c94f4f",
    "low": "#5c636a", "info": "#868e96",
}

__all__ = [
    "RED", "RED_PRINT", "RED_BRIGHT", "RED_DARK", "RED_LINK",
    "WHITE", "BLACK", "INK", "GREY", "GREY_DIM", "LINE", "LINE_LIGHT",
    "CODE_DARK_BG", "PANEL", "SEVERITY_ON_DARK", "SEVERITY_FILL",
]
