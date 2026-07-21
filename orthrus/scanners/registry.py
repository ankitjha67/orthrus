"""Scanner registry - the extension point for vulnerability modules.

Scanner classes register here (via the ``@register`` decorator) keyed by their
``vuln_type``. The orchestrator resolves the operator's ``--modules`` selection
against this registry. No scanners are built yet (Roadmap Phase 2+); this is the
seam they slot into.
"""

from __future__ import annotations

from orthrus.scanners.base_scanner import BaseScanner

# Keyed by unique scanner ``name`` so multiple scanners can share a vuln_type
# (e.g. reflected-xss, dom-xss, stored-xss all report vuln_type="xss").
SCANNER_REGISTRY: dict[str, type[BaseScanner]] = {}


def register(cls: type[BaseScanner]) -> type[BaseScanner]:
    SCANNER_REGISTRY[cls.name] = cls
    return cls


def get_scanners(modules: list[str]) -> list[BaseScanner]:
    if not modules or modules == ["all"]:
        return [cls() for cls in SCANNER_REGISTRY.values()]
    selected = set(modules)
    return [
        cls()
        for cls in SCANNER_REGISTRY.values()
        if cls.name in selected or cls.vuln_type in selected
    ]


def available_modules() -> list[str]:
    return sorted(SCANNER_REGISTRY)


__all__ = ["SCANNER_REGISTRY", "register", "get_scanners", "available_modules"]
