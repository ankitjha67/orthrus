"""Scanner registry — the extension point for vulnerability modules.

Scanner classes register here (via the ``@register`` decorator) keyed by their
``vuln_type``. The orchestrator resolves the operator's ``--modules`` selection
against this registry. No scanners are built yet (Roadmap Phase 2+); this is the
seam they slot into.
"""

from __future__ import annotations

from hydra.scanners.base_scanner import BaseScanner

SCANNER_REGISTRY: dict[str, type[BaseScanner]] = {}


def register(cls: type[BaseScanner]) -> type[BaseScanner]:
    key = cls.vuln_type or cls.name
    SCANNER_REGISTRY[key] = cls
    return cls


def get_scanners(modules: list[str]) -> list[BaseScanner]:
    if not modules or modules == ["all"]:
        return [cls() for cls in SCANNER_REGISTRY.values()]
    return [SCANNER_REGISTRY[m]() for m in modules if m in SCANNER_REGISTRY]


def available_modules() -> list[str]:
    return sorted(SCANNER_REGISTRY)


__all__ = ["SCANNER_REGISTRY", "register", "get_scanners", "available_modules"]
