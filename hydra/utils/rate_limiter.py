"""Async per-host rate limiting via token bucket.

Keeps HYDRA within the operator-configured requests-per-second to avoid
hammering targets (PRD §3.3 request rate limiting, §12.1 throttling with jitter).
Each host gets its own bucket so a slow host never starves a fast one.
"""

from __future__ import annotations

import asyncio
import random
import time


class TokenBucket:
    def __init__(self, rate: float, capacity: int) -> None:
        self.rate = max(rate, 0.001)
        self.capacity = max(capacity, 1)
        self.tokens = float(self.capacity)
        self.timestamp = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.timestamp) * self.rate)
                self.timestamp = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                await asyncio.sleep((1.0 - self.tokens) / self.rate)


class RateLimiter:
    """Manages one TokenBucket per host with optional jitter."""

    def __init__(self, requests_per_second: float, burst: int, jitter: float = 0.0) -> None:
        self.rps = requests_per_second
        self.burst = burst
        self.jitter = max(jitter, 0.0)
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()

    async def _bucket_for(self, host: str) -> TokenBucket:
        async with self._lock:
            bucket = self._buckets.get(host)
            if bucket is None:
                bucket = TokenBucket(self.rps, self.burst)
                self._buckets[host] = bucket
            return bucket

    async def acquire(self, host: str) -> None:
        bucket = await self._bucket_for(host)
        await bucket.acquire()
        if self.jitter:
            await asyncio.sleep(random.uniform(0, self.jitter))


__all__ = ["RateLimiter", "TokenBucket"]
