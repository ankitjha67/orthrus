"""Continuous recon engine (PRD §7.2) — the net-new operator subsystem.

Adapters (pure-Python sources + wrapped external tools) each discover assets and
normalize them into ``DiscoveredAsset`` records; the :class:`ReconEngine` runs
them for a Program's scope, folds results into the operator graph
(``ProgramGraph.record_asset`` — dedup + first/last-seen), flags wildcard-DNS
noise, and reports what's *new* since the last run. This is what turns a one-shot
scan into a program that watches its scope continuously.
"""

from orthrus.recon_engine import sources as _sources  # noqa: F401  (registers built-in sources)
from orthrus.recon_engine.base import (
    RECON_REGISTRY,
    DiscoveredAsset,
    ReconAdapter,
    ReconScope,
    get_recon_adapters,
    register_recon,
)
from orthrus.recon_engine.engine import ReconEngine, ReconResult

__all__ = [
    "DiscoveredAsset",
    "ReconAdapter",
    "ReconScope",
    "RECON_REGISTRY",
    "register_recon",
    "get_recon_adapters",
    "ReconEngine",
    "ReconResult",
]
