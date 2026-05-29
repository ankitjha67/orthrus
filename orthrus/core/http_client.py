"""Scope-enforced async HTTP engine.

Every request routed through this client is validated against the engagement
scope **before** transmission, rate-limited per host, and has its redirect
chain checked hop-by-hop (PRD §3.3, §12.3). Modules must use this client rather
than raw httpx so the safety boundary cannot be bypassed.
"""

from __future__ import annotations

import random
from types import TracebackType
from urllib.parse import urlsplit

import httpx

from orthrus.core.config import ScanConfig
from orthrus.core.event_bus import EventBus, EventType
from orthrus.core.session import Session
from orthrus.utils.logger import get_logger
from orthrus.utils.rate_limiter import RateLimiter
from orthrus.utils.scope import ScopeValidator, ScopeViolation

logger = get_logger("http_client")

# Realistic desktop browser User-Agents for rotation (PRD §12.1).
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]


class HttpClient:
    def __init__(
        self,
        scope: ScopeValidator,
        rate_limiter: RateLimiter,
        *,
        session: Session | None = None,
        event_bus: EventBus | None = None,
        timeout: float = 30.0,
        proxy: str | None = None,
        user_agent: str = "random",
        extra_headers: dict[str, str] | None = None,
        verify_tls: bool = False,
        http2: bool = True,
        max_redirects: int = 5,
    ) -> None:
        self.scope = scope
        self.rate_limiter = rate_limiter
        self.session = session or Session()
        self.event_bus = event_bus
        self.user_agent = user_agent
        self.extra_headers = extra_headers or {}
        self.max_redirects = max_redirects

        self.requests_sent = 0
        self.scope_violations = 0

        self._client = httpx.AsyncClient(
            follow_redirects=False,  # we follow manually to scope-check each hop
            timeout=httpx.Timeout(timeout),
            verify=verify_tls,
            http2=http2,
            proxy=proxy,
            cookies=self.session.cookies or None,
        )

    @classmethod
    def from_config(
        cls,
        config: ScanConfig,
        scope: ScopeValidator,
        *,
        event_bus: EventBus | None = None,
        session: Session | None = None,
    ) -> HttpClient:
        rate_limiter = RateLimiter(
            config.rate_limit.requests_per_second,
            config.rate_limit.burst,
            config.rate_limit.jitter,
            adaptive=config.rate_limit.adaptive,
        )
        return cls(
            scope,
            rate_limiter,
            session=session,
            event_bus=event_bus,
            timeout=config.timeout,
            proxy=config.proxy,
            user_agent=config.user_agent,
            extra_headers=config.extra_headers,
            verify_tls=config.verify_tls,
        )

    def _pick_user_agent(self) -> str:
        if self.user_agent and self.user_agent != "random":
            return self.user_agent
        return random.choice(USER_AGENTS)

    def _merge_headers(self, headers: dict[str, str] | None) -> dict[str, str]:
        merged = dict(self.session.default_headers())
        merged.update(self.extra_headers)
        merged["User-Agent"] = self._pick_user_agent()
        if headers:
            merged.update(headers)
        return merged

    async def _enforce_scope(self, url: str, *, is_redirect: bool = False) -> None:
        decision = self.scope.check(url)
        if decision.allowed:
            return
        self.scope_violations += 1
        if self.event_bus is not None:
            await self.event_bus.emit(EventType.SCOPE_VIOLATION, url=url, reason=decision.reason)
        if is_redirect:
            logger.warning("blocked out-of-scope redirect to %s (%s)", url, decision.reason)
            raise ScopeViolation(url, decision.reason)
        logger.warning("blocked out-of-scope request to %s (%s)", url, decision.reason)
        raise ScopeViolation(url, decision.reason)

    async def request(
        self,
        method: str,
        url: str,
        *,
        follow_redirects: bool = True,
        headers: dict[str, str] | None = None,
        **kwargs: object,
    ) -> httpx.Response:
        await self._enforce_scope(url)
        host = urlsplit(url).hostname or ""
        await self.rate_limiter.acquire(host)

        response = await self._client.request(
            method, url, headers=self._merge_headers(headers), **kwargs
        )
        self.requests_sent += 1
        self.rate_limiter.feedback(
            host, status=response.status_code, retry_after=response.headers.get("retry-after")
        )

        if follow_redirects:
            response = await self._follow_redirects(response)
        return response

    async def _follow_redirects(self, response: httpx.Response) -> httpx.Response:
        hops = 0
        while response.is_redirect and hops < self.max_redirects:
            location = response.headers.get("location")
            if not location:
                break
            try:
                next_url = str(response.url.join(location))
            except httpx.InvalidURL:
                logger.debug("stopping at malformed redirect Location %r", location)
                break
            try:
                await self._enforce_scope(next_url, is_redirect=True)
            except ScopeViolation:
                break  # stop following but return what we already have
            next_host = urlsplit(next_url).hostname or ""
            await self.rate_limiter.acquire(next_host)
            response = await self._client.request(
                "GET", next_url, headers=self._merge_headers(None)
            )
            self.requests_sent += 1
            self.rate_limiter.feedback(
                next_host,
                status=response.status_code,
                retry_after=response.headers.get("retry-after"),
            )
            hops += 1
        return response

    async def get(self, url: str, **kwargs: object) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: object) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs: object) -> httpx.Response:
        kwargs.setdefault("follow_redirects", False)
        return await self.request("HEAD", url, **kwargs)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> HttpClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()


__all__ = ["HttpClient", "USER_AGENTS"]
