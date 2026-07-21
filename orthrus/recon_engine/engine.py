"""The recon engine (PRD §7.2): run adapters → fold into the operator graph.

Runs every available adapter for a program's scope, deduplicates + records the
results into the graph (``record_asset`` handles identity + first/last-seen),
flags wildcard-DNS noise, and reports what's genuinely *new* since the last run —
the signal continuous recon exists to surface. Network access (DNS resolution) is
injected so the engine is fully unit-testable offline.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from orthrus.model.store import ProgramGraph
from orthrus.recon_engine.base import ReconAdapter, ReconScope
from orthrus.utils.logger import get_logger

logger = get_logger("recon_engine")

Resolver = Callable[[str], Awaitable[list[str]]]

# Unlikely labels used to fingerprint wildcard DNS (if these resolve, the zone
# answers for anything, so real subdomains must be told apart by IP).
_WILDCARD_PROBES = ("orthrus-nx-a1b2c3", "zzq-does-not-exist-9182", "no-such-host-4471")


async def _default_resolve(name: str) -> list[str]:
    from orthrus.recon.subdomain_enum import _resolve
    return await _resolve(name)


def _canonical(value: str) -> str:
    return (value or "").strip().lower().rstrip(".")


@dataclass
class ReconResult:
    program_id: str
    sources_run: list[str] = field(default_factory=list)
    discovered: int = 0
    recorded: int = 0
    new: list[str] = field(default_factory=list)
    wildcard_noise: int = 0
    failed_sources: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (f"{len(self.sources_run)} source(s) · {self.discovered} discovered · "
                f"{len(self.new)} NEW · {self.wildcard_noise} wildcard-noise")


class ReconEngine:
    def __init__(
        self,
        graph: ProgramGraph,
        adapters: list[ReconAdapter],
        *,
        resolve: Resolver | None = None,
    ) -> None:
        self.graph = graph
        self.adapters = adapters
        self.resolve = resolve or _default_resolve

    async def _wildcard_ips(self, domain: str) -> set[str]:
        """The IP set a wildcard zone answers with, or empty if no wildcard."""
        answers: list[set[str]] = []
        for label in _WILDCARD_PROBES:
            ips = await self.resolve(f"{label}.{domain}")
            if ips:
                answers.append(set(ips))
        # A wildcard resolves *every* random label to the same IP(s).
        if len(answers) >= 2:
            common = set.intersection(*answers)
            if common:
                return common
        return set()

    async def _is_noise(self, value: str, kind: str, wildcards: dict[str, set[str]]) -> bool:
        if kind not in ("subdomain", "host") or not wildcards:
            return False
        for domain, wips in wildcards.items():
            if value == domain or value.endswith("." + domain):
                ips = set(await self.resolve(value))
                if ips and ips <= wips:      # resolves only to the wildcard IPs → noise
                    return True
        return False

    async def run(self, program_id: str, scope: ReconScope) -> ReconResult:
        result = ReconResult(program_id=program_id)

        wildcards: dict[str, set[str]] = {}
        for domain in scope.domains:
            wips = await self._wildcard_ips(domain)
            if wips:
                wildcards[domain] = wips

        discovered = []
        for adapter in self.adapters:
            if not adapter.available():
                logger.info("recon adapter '%s' unavailable (binary missing) — skipping", adapter.name)
                continue
            result.sources_run.append(adapter.name)
            try:
                discovered.extend(await adapter.discover(scope))
            except Exception:  # noqa: BLE001  (one bad source must not kill the run)
                logger.exception("recon adapter '%s' failed", adapter.name)
                result.failed_sources.append(adapter.name)
        result.discovered = len(discovered)

        seen: set[tuple[str, str]] = set()
        for asset in discovered:
            cv = _canonical(asset.value)
            if not cv:
                continue
            key = (asset.kind, cv)
            if key in seen:
                continue
            seen.add(key)
            noise = await self._is_noise(cv, asset.kind, wildcards)
            _row, is_new = await self.graph.record_asset(
                program_id, asset.kind, cv, asset.value,
                discovered_by=asset.source, metadata=asset.metadata or None,
                wildcard_noise=noise,
            )
            result.recorded += 1
            if noise:
                result.wildcard_noise += 1
            elif is_new:
                result.new.append(cv)
        return result


__all__ = ["ReconEngine", "ReconResult"]
