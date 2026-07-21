"""New-asset alert message builder (PRD §7.9)."""

from __future__ import annotations

from orthrus.recon_engine.alerts import new_asset_message


def test_message_lists_assets_and_counts():
    msg = new_asset_message("Acme", ["a.acme.com", "b.acme.com"])
    assert "Acme" in msg and "2 NEW in-scope asset(s)" in msg
    assert "• a.acme.com" in msg and "• b.acme.com" in msg


def test_message_caps_long_lists():
    assets = [f"h{i}.acme.com" for i in range(40)]
    msg = new_asset_message("Acme", assets)
    assert "40 NEW in-scope asset(s)" in msg
    assert "…and 15 more" in msg                 # 40 - 25 shown
    assert msg.count("•") == 25


def test_message_header_only_when_empty():
    msg = new_asset_message("Acme", [])
    assert "0 NEW in-scope asset(s)" in msg and "•" not in msg
