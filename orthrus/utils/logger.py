"""Structured logging with rich console output.

A single shared Console (on stderr, so report data on stdout stays clean) is
used across the framework. Call :func:`configure_logging` once at startup; every
module then uses :func:`get_logger`.
"""

from __future__ import annotations

import logging

from rich.console import Console
from rich.logging import RichHandler

from orthrus.utils.theme import ORTHRUS_THEME

# Shared stderr console (stdout stays clean for report data). The theme
# registers ORTHRUS's palette so log markup and tables share one design language.
console = Console(stderr=True, theme=ORTHRUS_THEME)

_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}

_configured = False


def configure_logging(level: str = "info") -> None:
    global _configured
    log_level = _LEVELS.get(level.lower(), logging.INFO)
    handler = RichHandler(
        console=console,
        rich_tracebacks=True,
        show_path=False,
        markup=True,
        omit_repeated_times=False,
    )
    root = logging.getLogger("orthrus")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(log_level)
    root.propagate = False
    _configured = True


def get_logger(name: str) -> logging.Logger:
    if not _configured:
        configure_logging()
    if not name.startswith("orthrus"):
        name = f"orthrus.{name}"
    return logging.getLogger(name)


__all__ = ["configure_logging", "get_logger", "console"]
