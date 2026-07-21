"""Emergency kill switch (PRD §8.3): panic flag + HTTP-client deny-everything."""

from __future__ import annotations

import httpx
import pytest

from orthrus.core import panic
from orthrus.core.config import ScopeConfig
from orthrus.core.http_client import HttpClient
from orthrus.utils.rate_limiter import RateLimiter
from orthrus.utils.scope import ScopeValidator, ScopeViolation


def test_engage_details_and_clear(tmp_path, monkeypatch):
    monkeypatch.setenv("ORTHRUS_HOME", str(tmp_path))
    assert panic.is_engaged() is False
    panic.engage("compromised target")
    assert panic.is_engaged() is True
    assert panic.details()["reason"] == "compromised target"
    assert panic.clear() is True
    assert panic.is_engaged() is False
    assert panic.clear() is False  # nothing to clear


def _client() -> HttpClient:
    scope = ScopeValidator(ScopeConfig(domains=["example.com"]))
    client = HttpClient(scope, RateLimiter(1000.0, burst=1000, adaptive=False))
    client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _req: httpx.Response(200, text="ok"))
    )
    return client


async def test_panic_denies_every_request(tmp_path, monkeypatch):
    monkeypatch.setenv("ORTHRUS_HOME", str(tmp_path))
    client = _client()

    # engaged: even an otherwise-in-scope host is denied, and the reason names PANIC
    panic.engage("stop")
    with pytest.raises(ScopeViolation) as ei:
        await client._enforce_scope("http://example.com/")
    assert "PANIC" in str(ei.value)
    assert client.scope_violations == 1

    # cleared: normal scope enforcement resumes - an out-of-scope host is still
    # denied, but NOT for a panic reason (proves panic no longer short-circuits)
    panic.clear()
    with pytest.raises(ScopeViolation) as ei2:
        await client._enforce_scope("http://out-of-scope.example.net/")
    assert "PANIC" not in str(ei2.value)

    await client._client.aclose()
