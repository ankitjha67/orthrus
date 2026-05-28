"""Tests for the XXE payload construction (detection reuses LFI signatures)."""

from __future__ import annotations

from hydra.scanners.xxe import xxe_payloads


def test_payloads_declare_external_entities():
    payloads = xxe_payloads()
    assert payloads
    for p in payloads:
        assert "<!ENTITY" in p
        assert "SYSTEM" in p
        assert "&xxe;" in p


def test_payloads_cover_unix_and_windows():
    joined = " ".join(xxe_payloads())
    assert "/etc/passwd" in joined
    assert "win.ini" in joined
