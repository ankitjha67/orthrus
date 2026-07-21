"""Recon adapter framework (PRD §7.2).

Every recon source — a pure-Python API client (crt.sh, certspotter, wayback) or a
wrapped external binary (subfinder, dnsx, httpx) — implements :class:`ReconAdapter`
and yields :class:`DiscoveredAsset` records. The engine normalizes and dedups them
into the operator graph, so adding a new source is one small class, not new
plumbing. Adapters that need a binary self-skip when it isn't installed, exactly
like the finding-producing ``orthrus.integrations`` adapters.
"""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class DiscoveredAsset:
    """One asset a recon source found, before it's folded into the graph."""

    kind: str                                   # an ASSET_KINDS value
    value: str                                  # raw discovered value (host, url, ip, …)
    source: str                                 # adapter name that found it
    metadata: dict = field(default_factory=dict)


@dataclass
class ReconScope:
    """The in-scope surface an adapter is allowed to enumerate for a program."""

    domains: list[str] = field(default_factory=list)   # apex/root domains in scope
    program_id: str = ""


class ReconAdapter(ABC):
    name: str = "adapter"
    binary: str = ""          # external binary, if any; empty = pure Python (always available)

    def available(self) -> bool:
        return not self.binary or shutil.which(self.binary) is not None

    @abstractmethod
    async def discover(self, scope: ReconScope) -> list[DiscoveredAsset]:
        """Enumerate assets for ``scope``. Must not touch anything out of scope."""
        raise NotImplementedError


RECON_REGISTRY: dict[str, type[ReconAdapter]] = {}


def register_recon(cls: type[ReconAdapter]) -> type[ReconAdapter]:
    RECON_REGISTRY[cls.name] = cls
    return cls


def get_recon_adapters(names: Iterable[str] | None = None) -> list[ReconAdapter]:
    """Instantiate registered adapters (all, or a named subset; 'all' = every one)."""
    if names is None:
        return [cls() for cls in RECON_REGISTRY.values()]
    selected = {n.strip().lower() for n in names if n and n.strip()}
    if "all" in selected:
        return [cls() for cls in RECON_REGISTRY.values()]
    return [cls() for name, cls in RECON_REGISTRY.items() if name in selected]


__all__ = [
    "DiscoveredAsset",
    "ReconScope",
    "ReconAdapter",
    "RECON_REGISTRY",
    "register_recon",
    "get_recon_adapters",
]
