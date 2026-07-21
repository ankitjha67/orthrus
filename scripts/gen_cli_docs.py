#!/usr/bin/env python3
"""Generate `docs/CLI.md` from the ORTHRUS Click command tree.

Keeps the CLI reference always accurate and diffable. Run from the repo root:

    python scripts/gen_cli_docs.py

(force UTF-8 on Windows: ``PYTHONUTF8=1 python scripts/gen_cli_docs.py``).
"""

from __future__ import annotations

import pathlib

import click

from orthrus.main import cli


def _help(cmd: click.Command, info_name: str, parent: click.Context | None = None) -> str:
    ctx = click.Context(cmd, info_name=info_name, parent=parent)
    return cmd.get_help(ctx).replace("\r\n", "\n").rstrip()


def render() -> str:
    root = click.Context(cli, info_name="orthrus")
    names = sorted(cli.commands)
    out = [
        "# ORTHRUS CLI reference",
        "",
        "_Auto-generated from the Click command tree - regenerate with_ "
        "`python scripts/gen_cli_docs.py`_._",
        "",
        "## `orthrus`",
        "",
        "```text",
        _help(cli, "orthrus"),
        "```",
        "",
        "**Commands:** " + " · ".join(f"[`{n}`](#orthrus-{n})" for n in names),
        "",
    ]
    for n in names:
        out += [f"## `orthrus {n}`", "", "```text", _help(cli.commands[n], n, parent=root), "```", ""]
    return "\n".join(out) + "\n"


def main() -> None:
    dest = pathlib.Path(__file__).resolve().parent.parent / "docs" / "CLI.md"
    dest.write_text(render(), encoding="utf-8")
    print(f"wrote {dest} ({len(cli.commands)} commands)")


if __name__ == "__main__":
    main()
