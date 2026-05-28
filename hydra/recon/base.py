"""Abstract reconnaissance module interface.

A recon module discovers assets and/or endpoints and yields them. The
orchestrator routes each yielded object to the correct persistence path based
on its type, so a module can emit a mix (e.g. a crawler emits Endpoints; a
subdomain enumerator emits Assets).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

from hydra.core import schemas
from hydra.core.context import ScanContext

ReconResult = schemas.Asset | schemas.Endpoint


class BaseRecon(ABC):
    name: str = "base-recon"

    def applicable(self, ctx: ScanContext) -> bool:
        """Return False to skip this module for the given engagement."""
        return True

    @abstractmethod
    def discover(self, ctx: ScanContext) -> AsyncIterator[ReconResult]:
        """Async generator yielding discovered Assets and/or Endpoints."""
        raise NotImplementedError


__all__ = ["BaseRecon", "ReconResult"]
