"""Tests for plugin discovery + external-dir loading."""

from __future__ import annotations

from hydra.plugins import load_plugins
from hydra.scanners.registry import SCANNER_REGISTRY


def test_builtin_example_plugin_registers():
    loaded = load_plugins()
    assert "example_plugin" in loaded
    assert "example-server-banner" in SCANNER_REGISTRY


def test_external_plugin_dir(tmp_path):
    plugin = tmp_path / "my_plugin.py"
    plugin.write_text(
        "from hydra.scanners.base_scanner import BaseScanner\n"
        "from hydra.scanners.registry import register\n"
        "@register\n"
        "class MyPlugin(BaseScanner):\n"
        "    name = 'unit-test-plugin'\n"
        "    vuln_type = 'demo'\n"
        "    async def scan(self, ctx):\n"
        "        return\n"
        "        yield\n",
        encoding="utf-8",
    )
    loaded = load_plugins(str(tmp_path))
    assert "my_plugin" in loaded
    assert "unit-test-plugin" in SCANNER_REGISTRY
