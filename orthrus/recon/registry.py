"""Recon plugin registry (PRD §13.1 Recon Plugin).

Built-in recon modules are wired directly by the orchestrator; plugin recon
modules register here and are run in addition to the built-ins.
"""

from __future__ import annotations

from orthrus.recon.base import BaseRecon

RECON_REGISTRY: dict[str, type[BaseRecon]] = {}


def register(cls: type[BaseRecon]) -> type[BaseRecon]:
    RECON_REGISTRY[cls.name] = cls
    return cls


def get_recon_plugins() -> list[BaseRecon]:
    return [cls() for cls in RECON_REGISTRY.values()]


__all__ = ["RECON_REGISTRY", "register", "get_recon_plugins"]
