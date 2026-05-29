"""Tests for the token-bucket limiter and adaptive (AIMD) back-off policy."""

from __future__ import annotations

import calendar
import time

import httpx

from orthrus.core.config import ScopeConfig
from orthrus.core.http_client import HttpClient
from orthrus.utils.rate_limiter import (
    AdaptiveRate,
    RateLimiter,
    TokenBucket,
    parse_retry_after,
)
from orthrus.utils.scope import ScopeValidator


# --------------------------------------------------------- parse_retry_after
def test_retry_after_seconds():
    assert parse_retry_after("120") == 120.0
    assert parse_retry_after("0") == 0.0


def test_retry_after_absent_or_blank():
    assert parse_retry_after(None) is None
    assert parse_retry_after("   ") is None


def test_retry_after_http_date_future_and_past():
    target = "Wed, 21 Oct 2015 07:28:30 GMT"
    # calendar.timegm is the UTC inverse of the GMT date, matching how
    # parse_retry_after derives the timestamp internally.
    epoch = calendar.timegm(time.strptime(target, "%a, %d %b %Y %H:%M:%S GMT"))
    fut = parse_retry_after(target, now=epoch - 30)
    assert fut is not None and 29 <= fut <= 31
    past = parse_retry_after(target, now=epoch + 1800)  # date already elapsed
    assert past == 0.0


def test_retry_after_garbage_is_none():
    assert parse_retry_after("soon-ish") is None


# ------------------------------------------------------------- AdaptiveRate
def test_adaptive_multiplicative_decrease_with_floor():
    a = AdaptiveRate(floor=0.1, decrease=0.5)
    a.on_throttle()
    assert a.factor == 0.5
    a.on_throttle()
    assert a.factor == 0.25
    for _ in range(10):
        a.on_throttle()
    assert a.factor == 0.1  # clamped at the floor, never zero


def test_adaptive_additive_recovery_after_streak():
    a = AdaptiveRate(decrease=0.5, increase=0.1, recover_after=3)
    a.on_throttle()  # factor 0.5
    a.on_success()
    a.on_success()
    assert a.factor == 0.5  # not enough successes yet
    a.on_success()
    assert abs(a.factor - 0.6) < 1e-9  # recovered one step after 3 successes


def test_adaptive_success_is_noop_at_full_rate():
    a = AdaptiveRate()
    for _ in range(100):
        a.on_success()
    assert a.factor == 1.0  # never exceeds the configured rate


def test_adaptive_throttle_resets_success_streak():
    a = AdaptiveRate(decrease=0.5, increase=0.1, recover_after=3)
    a.on_throttle()
    a.on_success()
    a.on_success()
    a.on_throttle()  # resets the streak and decreases again
    assert a.factor == 0.25
    a.on_success()
    assert a.factor == 0.25  # streak restarted from zero


def test_adaptive_recovery_caps_at_one():
    a = AdaptiveRate(decrease=0.5, increase=0.4, recover_after=1)
    a.on_throttle()  # 0.5
    a.on_success()  # 0.9
    a.on_success()  # would be 1.3 -> clamped to 1.0
    assert a.factor == 1.0


# --------------------------------------------------------------- TokenBucket
async def test_token_bucket_set_rate_floor():
    b = TokenBucket(rate=10, capacity=5)
    b.set_rate(0)
    assert b.rate == 0.001  # never zero (would divide-by-zero on sleep math)


# ---------------------------------------------------------------- RateLimiter
async def test_feedback_lowers_then_recovers_effective_rate():
    rl = RateLimiter(100.0, burst=100, adaptive=True)
    await rl.acquire("h")  # creates the bucket
    assert rl.current_rate("h") == 100.0
    rl.feedback("h", status=429)
    assert rl.current_rate("h") == 50.0  # halved on 429
    rl.feedback("h", status=503)
    assert rl.current_rate("h") == 25.0  # halved again on 503
    # five successes (default recover_after) nudge the rate back up one step
    for _ in range(5):
        rl.feedback("h", status=200)
    assert rl.current_rate("h") > 25.0


async def test_feedback_noop_when_adaptive_disabled():
    rl = RateLimiter(40.0, burst=10, adaptive=False)
    await rl.acquire("h")
    rl.feedback("h", status=429, retry_after="10")
    assert rl.current_rate("h") == 40.0  # unchanged


async def test_retry_after_sets_penalty_window():
    rl = RateLimiter(100.0, burst=100, adaptive=True, max_penalty=30.0)
    await rl.acquire("h")
    rl.feedback("h", status=429, retry_after="5")
    remaining = rl._penalty_until["h"] - time.monotonic()
    assert 4.0 < remaining <= 5.0  # ~5s pause scheduled


async def test_retry_after_capped_at_max_penalty():
    rl = RateLimiter(100.0, burst=100, adaptive=True, max_penalty=2.0)
    await rl.acquire("h")
    rl.feedback("h", status=503, retry_after="3600")  # malicious/huge value
    remaining = rl._penalty_until["h"] - time.monotonic()
    assert remaining <= 2.0  # clamped so a scan can't be stalled for an hour


async def test_per_host_isolation():
    rl = RateLimiter(100.0, burst=100, adaptive=True)
    await rl.acquire("a")
    await rl.acquire("b")
    rl.feedback("a", status=429)
    assert rl.current_rate("a") == 50.0
    assert rl.current_rate("b") == 100.0  # a slow host doesn't drag down others


# ----------------------------------------------- HttpClient feedback wiring
async def test_http_client_backs_off_on_429():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "1"}, text="slow down")

    scope = ScopeValidator(ScopeConfig(domains=["test.local"], ports=[80]))
    rl = RateLimiter(100.0, burst=100, adaptive=True, max_penalty=2.0)
    client = HttpClient(scope, rl)
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        resp = await client.get("http://test.local/x", follow_redirects=False)
        assert resp.status_code == 429
        # the 429 fed back through the client halved the per-host rate
        assert rl.current_rate("test.local") == 50.0
        # and Retry-After scheduled a (capped) hard pause
        assert 0 < rl._penalty_until["test.local"] - time.monotonic() <= 2.0
    finally:
        await client.aclose()
