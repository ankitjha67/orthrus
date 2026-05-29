"""Async per-host rate limiting via token bucket, with adaptive back-off.

Keeps ORTHRUS within the operator-configured requests-per-second to avoid
hammering targets (PRD §3.3 request rate limiting, §12.1 throttling with jitter).
Each host gets its own bucket so a slow host never starves a fast one.

On top of the static limit, the limiter *adapts* to server feedback: a target
that answers ``429 Too Many Requests`` or ``503 Service Unavailable`` is telling
us to slow down, so the per-host rate is cut multiplicatively and recovered
additively as requests start succeeding again (AIMD — the same control law TCP
congestion control uses). A ``Retry-After`` header is honored as a hard pause.
This is what real scanners do to stay polite and avoid being blocked mid-scan.
"""

from __future__ import annotations

import asyncio
import random
import time
from email.utils import parsedate_to_datetime

from orthrus.utils.logger import get_logger

logger = get_logger("rate_limiter")

# Statuses where the server is explicitly asking us to back off.
THROTTLE_STATUSES = frozenset({429, 503})


def parse_retry_after(value: str | None, *, now: float | None = None) -> float | None:
    """Parse a ``Retry-After`` header into seconds-from-now.

    Accepts the two RFC 7231 forms — a delta-seconds integer or an HTTP-date —
    and returns a non-negative float, or ``None`` if absent/unparseable. ``now``
    (epoch seconds) is injectable for deterministic tests of the date form.
    """
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    if value.isdigit():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    reference = now if now is not None else time.time()
    delta = when.timestamp() - reference
    return max(0.0, delta)


class AdaptiveRate:
    """Per-host throttle multiplier driven by server feedback (pure policy).

    Holds a ``factor`` in ``(0, 1]`` that scales the configured rate:
    multiplicative *decrease* on a throttle signal, additive *increase* after a
    run of successes. No I/O or clock here, so the control law is unit-testable
    in isolation; the time-based parts live in :class:`RateLimiter`.
    """

    def __init__(
        self,
        *,
        floor: float = 0.05,
        decrease: float = 0.5,
        increase: float = 0.1,
        recover_after: int = 5,
    ) -> None:
        self.floor = floor
        self.decrease = decrease
        self.increase = increase
        self.recover_after = max(recover_after, 1)
        self.factor = 1.0
        self._successes = 0

    def on_throttle(self) -> None:
        self.factor = max(self.floor, self.factor * self.decrease)
        self._successes = 0

    def on_success(self) -> None:
        if self.factor >= 1.0:
            return
        self._successes += 1
        if self._successes >= self.recover_after:
            self.factor = min(1.0, self.factor + self.increase)
            self._successes = 0


class TokenBucket:
    def __init__(self, rate: float, capacity: int) -> None:
        self.rate = max(rate, 0.001)
        self.capacity = max(capacity, 1)
        self.tokens = float(self.capacity)
        self.timestamp = time.monotonic()
        self._lock = asyncio.Lock()

    def set_rate(self, rate: float) -> None:
        """Adjust the refill rate in place (used by adaptive back-off)."""
        self.rate = max(rate, 0.001)

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
    """Manages one TokenBucket per host with optional jitter and adaptive back-off."""

    def __init__(
        self,
        requests_per_second: float,
        burst: int,
        jitter: float = 0.0,
        *,
        adaptive: bool = True,
        max_penalty: float = 30.0,
    ) -> None:
        self.rps = requests_per_second
        self.burst = burst
        self.jitter = max(jitter, 0.0)
        self.adaptive = adaptive
        self.max_penalty = max(max_penalty, 0.0)
        self._buckets: dict[str, TokenBucket] = {}
        self._adaptive: dict[str, AdaptiveRate] = {}
        self._penalty_until: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def _bucket_for(self, host: str) -> TokenBucket:
        async with self._lock:
            bucket = self._buckets.get(host)
            if bucket is None:
                bucket = TokenBucket(self.rps, self.burst)
                self._buckets[host] = bucket
            return bucket

    async def acquire(self, host: str) -> None:
        if self.adaptive:
            await self._honor_penalty(host)
        bucket = await self._bucket_for(host)
        await bucket.acquire()
        if self.jitter:
            await asyncio.sleep(random.uniform(0, self.jitter))

    async def _honor_penalty(self, host: str) -> None:
        until = self._penalty_until.get(host)
        if until is None:
            return
        delay = until - time.monotonic()
        if delay > 0:
            await asyncio.sleep(delay)
        else:
            self._penalty_until.pop(host, None)

    def feedback(self, host: str, *, status: int, retry_after: str | None = None) -> None:
        """Adjust the per-host rate from a response's status / Retry-After header.

        Cheap and synchronous so the HTTP client can call it on every response.
        A no-op unless adaptive mode is on; the bucket already exists because
        ``acquire`` ran before the request was sent.
        """
        if not self.adaptive:
            return
        adaptive = self._adaptive.get(host)
        if adaptive is None:
            adaptive = AdaptiveRate()
            self._adaptive[host] = adaptive

        if status in THROTTLE_STATUSES:
            before = adaptive.factor
            adaptive.on_throttle()
            secs = parse_retry_after(retry_after)
            if secs is not None:
                self._penalty_until[host] = time.monotonic() + min(secs, self.max_penalty)
            self._apply_rate(host, adaptive.factor)
            if adaptive.factor < before:
                logger.info(
                    "backing off %s after HTTP %s (rate x%.2f%s)",
                    host,
                    status,
                    adaptive.factor,
                    f", retry-after {secs:.0f}s" if secs else "",
                )
        else:
            adaptive.on_success()
            self._apply_rate(host, adaptive.factor)

    def _apply_rate(self, host: str, factor: float) -> None:
        bucket = self._buckets.get(host)
        if bucket is not None:
            bucket.set_rate(self.rps * factor)

    def current_rate(self, host: str) -> float:
        """Effective requests-per-second for ``host`` after any adaptive back-off."""
        bucket = self._buckets.get(host)
        return bucket.rate if bucket is not None else self.rps


__all__ = ["RateLimiter", "TokenBucket", "AdaptiveRate", "parse_retry_after", "THROTTLE_STATUSES"]
