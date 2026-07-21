"""DNS-rebinding / SSRF-via-scope guard in the HTTP client.

The string scope check validates a request's *hostname*; this guard validates
where that name actually *resolves*. An in-scope domain must not be usable to
reach an internal/reserved address (loopback, RFC-1918, 169.254.x, …) unless the
engagement explicitly authorized that IP range. Resolution is monkeypatched so
the test needs no network.
"""

from __future__ import annotations

import httpx
import pytest

from orthrus.core.config import ScopeConfig
from orthrus.core.http_client import HttpClient
from orthrus.utils.rate_limiter import RateLimiter
from orthrus.utils.scope import ScopeValidator, ScopeViolation


def _client(scope_config: ScopeConfig, resolves_to: list[str]) -> HttpClient:
    scope = ScopeValidator(scope_config)
    client = HttpClient(scope, RateLimiter(1000.0, burst=1000, adaptive=False))
    client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _req: httpx.Response(200, text="ok"))
    )

    async def _fake_resolve(host: str, port: int | None) -> list[str]:
        return resolves_to

    client._resolve_host = _fake_resolve  # type: ignore[assignment]
    return client


async def test_blocks_domain_that_resolves_to_link_local_metadata():
    # cloud metadata IP - the classic SSRF-via-rebinding target.
    client = _client(ScopeConfig(domains=["app.target.test"], ports=[]), ["169.254.169.254"])
    with pytest.raises(ScopeViolation):
        await client._enforce_scope("http://app.target.test/")
    await client.aclose()


async def test_blocks_domain_that_resolves_to_private_rfc1918():
    client = _client(ScopeConfig(domains=["app.target.test"], ports=[]), ["10.0.0.5"])
    with pytest.raises(ScopeViolation):
        await client.request("GET", "http://app.target.test/")  # end-to-end: send is blocked
    assert client.requests_sent == 0
    await client.aclose()


async def test_allows_domain_that_resolves_to_public_ip():
    client = _client(ScopeConfig(domains=["app.target.test"], ports=[]), ["93.184.216.34"])
    await client._enforce_scope("http://app.target.test/")  # no raise
    await client.aclose()


async def test_allows_internal_ip_when_explicitly_in_ip_ranges():
    # Internal engagement: 10.0.0.0/8 is authorized, so a host resolving there is fine.
    client = _client(
        ScopeConfig(domains=["app.corp.test"], ip_ranges=["10.0.0.0/8"], ports=[]), ["10.0.0.5"]
    )
    await client._enforce_scope("http://app.corp.test/")  # no raise
    await client.aclose()


async def test_ip_literal_target_skips_resolution_guard():
    scope = ScopeValidator(ScopeConfig(ip_ranges=["127.0.0.1/32"], ports=[]))
    client = HttpClient(scope, RateLimiter(1000.0, burst=1000, adaptive=False))

    async def _boom(host: str, port: int | None) -> list[str]:
        raise AssertionError("must not resolve an IP literal")

    client._resolve_host = _boom  # type: ignore[assignment]
    await client._enforce_scope("http://127.0.0.1/")  # literal already validated → no resolve
    await client.aclose()


async def test_fails_open_when_host_unresolvable():
    client = _client(ScopeConfig(domains=["nx.target.test"], ports=[]), [])  # resolves to nothing
    await client._enforce_scope("http://nx.target.test/")  # no raise (httpx will attempt & fail)
    await client.aclose()


async def test_verdict_is_cached_per_host():
    client = _client(ScopeConfig(domains=["app.target.test"], ports=[]), ["10.0.0.5"])
    with pytest.raises(ScopeViolation):
        await client._enforce_scope("http://app.target.test/")
    # Second call hits the cache and still blocks, even if resolution now errors.
    async def _boom(host: str, port: int | None) -> list[str]:
        raise AssertionError("should have used the cached verdict")

    client._resolve_host = _boom  # type: ignore[assignment]
    with pytest.raises(ScopeViolation):
        await client._enforce_scope("http://app.target.test/")
    await client.aclose()
