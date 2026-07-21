"""New-asset alerts (PRD §7.9) - the delivery half of "new asset → notification".

A plain-text summary that reads well in both Slack (as ``{"text": …}``) and
Discord (as ``content``), so a fresh in-scope host surfaces the moment recon
finds it.
"""

from __future__ import annotations

_MAX_SHOWN = 25


def new_asset_message(program_name: str, new_assets: list[str]) -> str:
    """Human-readable summary of newly-discovered in-scope assets."""
    n = len(new_assets)
    shown = new_assets[:_MAX_SHOWN]
    lines = "\n".join(f"• {a}" for a in shown)
    more = f"\n…and {n - _MAX_SHOWN} more" if n > _MAX_SHOWN else ""
    header = f"🛰 ORTHRUS · {program_name or 'program'}: {n} NEW in-scope asset(s)"
    return f"{header}\n{lines}{more}" if shown else header


__all__ = ["new_asset_message"]
