"""Abstract scanner interface (PRD §6.1).

Every vulnerability scanner inherits from ``BaseScanner`` and implements
``scan`` as an async generator yielding ``Finding`` objects. Scanners receive
the full asset/endpoint inventory via the ScanContext and decide their own
injection points. Aggressiveness gates how many/which payloads are sent.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Aggressiveness, Finding


class BaseScanner(ABC):
    name: str = "base"
    vuln_type: str = "generic"
    # Minimum aggressiveness at which this scanner runs (e.g. active scanners
    # that send payloads may require NORMAL; intrusive ones may require AGGRESSIVE).
    min_aggressiveness: Aggressiveness = Aggressiveness.PASSIVE

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    async def setup(self, ctx: ScanContext) -> None:
        """Optional one-time preparation before scanning begins."""

    @abstractmethod
    def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        """Async generator yielding Finding objects for this vulnerability class."""
        raise NotImplementedError

    async def teardown(self, ctx: ScanContext) -> None:
        """Optional cleanup after scanning completes."""


__all__ = ["BaseScanner"]
