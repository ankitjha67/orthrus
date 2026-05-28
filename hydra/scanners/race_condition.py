"""Race condition / TOCTOU scanner (PRD §6.8 Race Conditions).

Fires a burst of concurrent identical requests at transactional endpoints and
flags *partial* success (some accepted, some rejected) — the signature of a
race window where a once-only operation was granted more than once. Inherently
heuristic, so findings are TENTATIVE and aggressive-only.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import httpx

from hydra.core.context import ScanContext
from hydra.core.schemas import (
    Aggressiveness,
    Confidence,
    Evidence,
    Finding,
    HttpMethod,
    ParamLocation,
    Severity,
)
from hydra.scanners.base_scanner import BaseScanner
from hydra.scanners.registry import register
from hydra.utils.scope import ScopeViolation

SCANNER_NAME = "race-condition"
BURST = 8

TRANSACTIONAL_HINTS = {
    "coupon", "redeem", "transfer", "vote", "amount", "qty", "quantity",
    "purchase", "buy", "balance", "gift", "promo", "voucher", "withdraw",
    "apply", "claim", "order", "checkout", "credit", "points",
}


def race_signal(success_count: int, total: int) -> bool:
    """Partial success across a concurrent burst => contention on a once-only op."""
    return 1 < success_count < total


@register
class RaceConditionScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "race-condition"
    min_aggressiveness = Aggressiveness.AGGRESSIVE

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        for ep in ctx.endpoints:
            if ep.method != HttpMethod.POST or ep.source != "form":
                continue
            names = {p.name.lower() for p in ep.params}
            if not (names & TRANSACTIONAL_HINTS) or ep.url in seen:
                continue
            seen.add(ep.url)

            data = {
                p.name: (p.value or "1")
                for p in ep.params
                if p.location == ParamLocation.BODY
            }
            # Retry in a fresh window: one burst can spread across time and miss
            # the contention signal; a second round makes detection reliable.
            statuses: list[int] = []
            success = 0
            for attempt in range(2):
                statuses = await self._burst(ctx, ep.url, data)
                success = sum(1 for s in statuses if 200 <= s < 300)
                if race_signal(success, len(statuses)):
                    break
                if attempt == 0:
                    await asyncio.sleep(2.5)
            if race_signal(success, len(statuses)):
                yield Finding(
                    vuln_type="race-condition",
                    title=f"Possible race condition (TOCTOU) at {ep.url}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.TENTATIVE,
                    url=ep.url,
                    description=(
                        f"A burst of {len(statuses)} concurrent requests produced {success} "
                        "successes — a once-only operation appears to be granted multiple times "
                        "under concurrency. Manual verification required."
                    ),
                    remediation=(
                        "Serialize state-changing operations with locks / atomic DB constraints "
                        "(unique indexes, SELECT ... FOR UPDATE) and idempotency keys."
                    ),
                    cwe="CWE-362",
                    scanner=SCANNER_NAME,
                    evidence=Evidence(notes=f"burst statuses: {statuses}"),
                )

    async def _burst(self, ctx: ScanContext, url: str, data: dict) -> list[int]:
        async def one() -> int:
            try:
                resp = await ctx.http.post(url, data=data, follow_redirects=False)
                return resp.status_code
            except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL):
                return 0

        return list(await asyncio.gather(*[one() for _ in range(BURST)]))


__all__ = ["RaceConditionScanner", "race_signal"]
