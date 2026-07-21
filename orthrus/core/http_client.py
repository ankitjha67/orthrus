"""Scope-enforced async HTTP engine.

Every request routed through this client is validated against the engagement
scope **before** transmission, rate-limited per host, and has its redirect
chain checked hop-by-hop (PRD §3.3, §12.3). Modules must use this client rather
than raw httpx so the safety boundary cannot be bypassed.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import random
import socket
from types import TracebackType
from urllib.parse import urlsplit

import httpx

from orthrus.core import panic
from orthrus.core.auth import DEFAULT_REAUTH_MARKERS, looks_unauthenticated
from orthrus.core.block_detect import BlockMonitor, detect_block
from orthrus.core.config import ScanConfig
from orthrus.core.event_bus import EventBus, EventType
from orthrus.core.session import Session
from orthrus.utils.logger import get_logger
from orthrus.utils.rate_limiter import RateLimiter
from orthrus.utils.scope import ScopeValidator, ScopeViolation, _ip_in_ranges

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

# Cap the body slice handed to block detection — the signatures live near the
# top of a block page, and a full multi-MB body would be wasteful to scan.
_BLOCK_BODY_LIMIT = 20_000

# Hard ceiling on a single response body read into memory. A hostile target can
# otherwise return a multi-gigabyte — or endless chunked, or gzip-bomb — body to
# exhaust the scanner's memory. We stream the body and stop at the cap, counting
# DECODED bytes so a small compressed bomb that inflates hugely is also caught.
# Over-cap bodies are truncated (a scanner only needs the head of a document for
# its signatures); a 50 MB ceiling preserves virtually all legitimate responses.
_MAX_RESPONSE_BYTES = 50_000_000  # 50 MB


def _body_of(response: httpx.Response) -> str:
    try:
        return response.text[:_BLOCK_BODY_LIMIT]
    except Exception:  # noqa: BLE001  (decoding must never break block detection)
        return ""


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
        waf_adapt: bool = True,
        max_response_bytes: int = _MAX_RESPONSE_BYTES,
    ) -> None:
        self.scope = scope
        self.rate_limiter = rate_limiter
        self.session = session or Session()
        self.event_bus = event_bus
        self.user_agent = user_agent
        self.extra_headers = extra_headers or {}
        self.max_redirects = max_redirects
        self.max_response_bytes = max_response_bytes

        self.requests_sent = 0
        self.scope_violations = 0
        # DNS-rebinding guard: per-host verdict cache (hostname -> resolved-IP allowed).
        self._ip_scope_cache: dict[str, bool] = {}
        # Guard so a reauth hook (which itself issues requests) can't recurse.
        self._reauthing = False
        # Body markers that signal a dropped session; the orchestrator overrides
        # this from --reauth-marker. Only consulted when a reauth hook is set.
        self.reauth_markers: tuple[str, ...] = DEFAULT_REAUTH_MARKERS

        # Adaptive WAF / anti-automation resilience: classify each response for a
        # block/challenge, track the per-host block rate (scan-reliability signal),
        # and on a block rotate the request identity and retry once. The guard
        # stops the retry from itself triggering another evasion attempt.
        self.waf_adapt = waf_adapt
        self.block_monitor = BlockMonitor()
        self._evading = False
        self._last_ua: str | None = None
        self.block_backoff: tuple[float, float] = (0.4, 1.2)  # randomized cool-off range

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
            waf_adapt=config.waf_adapt,
        )

    def _pick_user_agent(self) -> str:
        ua = self.user_agent if (self.user_agent and self.user_agent != "random") \
            else random.choice(USER_AGENTS)
        self._last_ua = ua
        return ua

    def _rotate_user_agent(self) -> str:
        """Pick a UA different from the one last used (identity rotation on block)."""
        last = getattr(self, "_last_ua", None)
        pool = [ua for ua in USER_AGENTS if ua != last] or list(USER_AGENTS)
        ua = random.choice(pool)
        self._last_ua = ua
        return ua

    @staticmethod
    def _browser_headers(ua: str) -> dict[str, str]:
        """Realistic, UA-consistent default headers so requests don't read as a bot.

        Accept-Encoding is intentionally left to httpx (it advertises only what it
        can transparently decompress).
        """
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Upgrade-Insecure-Requests": "1",
        }
        if "Chrome/" in ua and "Firefox" not in ua:  # Chromium client-hints + fetch metadata
            platform = '"Windows"' if "Windows" in ua else (
                '"macOS"' if "Mac OS" in ua else '"Linux"')
            headers.update(
                {
                    "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", '
                    '"Not-A.Brand";v="99"',
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": platform,
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-User": "?1",
                    "Sec-Fetch-Dest": "document",
                }
            )
        return headers

    def _merge_headers(self, headers: dict[str, str] | None) -> dict[str, str]:
        ua = self._pick_user_agent()
        merged = self._browser_headers(ua)  # lowest priority: realistic browser defaults
        merged.update(self.session.default_headers())
        merged.update(self.extra_headers)
        merged["User-Agent"] = ua
        if headers:
            merged.update(headers)
        return merged

    def _evasion_headers(self, headers: dict[str, str] | None) -> dict[str, str]:
        """Header set for a block-retry: a fresh UA + matching browser headers."""
        ua = self._rotate_user_agent()
        merged = self._browser_headers(ua)
        if headers:
            merged.update(headers)
        merged["User-Agent"] = ua  # force the rotated identity even over caller headers
        return merged

    async def _resolve_host(self, host: str, port: int | None) -> list[str]:
        """Resolve a hostname to its IP address(es), async and best-effort."""
        try:
            loop = asyncio.get_running_loop()
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout=5.0
            )
        except (TimeoutError, OSError):
            return []  # unresolvable / slow → fail open; httpx will attempt & fail
        out: list[str] = []
        for info in infos:
            addr = str(info[4][0])
            if addr not in out:
                out.append(addr)
        return out

    @staticmethod
    def _ip_is_internal(ip: str) -> bool:
        try:
            obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return bool(
            obj.is_private or obj.is_loopback or obj.is_link_local
            or obj.is_reserved or obj.is_multicast or obj.is_unspecified
        )

    async def _enforce_resolved_ip(self, url: str, *, is_redirect: bool) -> None:
        """DNS-rebinding guard: an in-scope *hostname* must not resolve to an
        internal/reserved address (loopback, RFC-1918, link-local 169.254.x,
        multicast, …) unless that address is explicitly authorized in the
        engagement's ``ip_ranges``. The string scope check validates the *name*;
        this validates where it actually *points* — closing the SSRF-via-scope /
        rebinding gap where an authorized domain resolves to internal infra.
        """
        parts = urlsplit(url)
        host = parts.hostname or ""
        if not host:
            return
        try:
            ipaddress.ip_address(host)
            return  # already an IP literal — the string scope check validated it
        except ValueError:
            pass
        cached = self._ip_scope_cache.get(host)
        if cached is not None:
            if not cached:
                raise ScopeViolation(
                    url, "host resolves to a non-authorized internal address (DNS-rebinding guard)"
                )
            return
        ips = await self._resolve_host(host, parts.port)
        if not ips:
            return
        ranges = self.scope.scope.ip_ranges
        bad = next(
            (ip for ip in ips if self._ip_is_internal(ip) and not _ip_in_ranges(ip, ranges)), None
        )
        self._ip_scope_cache[host] = bad is None
        if bad is not None:
            self.scope_violations += 1
            if self.event_bus is not None:
                await self.event_bus.emit(
                    EventType.SCOPE_VIOLATION, url=url,
                    reason=f"{host} resolves to non-authorized address {bad}",
                )
            logger.warning(
                "blocked out-of-scope %s to %s — host resolves to internal address %s "
                "(DNS-rebinding guard)", "redirect" if is_redirect else "request", url, bad,
            )
            raise ScopeViolation(
                url, f"host resolves to non-authorized address {bad} (DNS-rebinding guard)"
            )

    async def _enforce_scope(self, url: str, *, is_redirect: bool = False) -> None:
        if panic.is_engaged():
            # Kill switch (PRD §8.3): panic turns deny-by-default into deny-everything.
            self.scope_violations += 1
            raise ScopeViolation(
                url, "PANIC engaged — all outbound requests halted "
                     "(lift with `orthrus panic --clear`)"
            )
        decision = self.scope.check(url)
        if decision.allowed:
            await self._enforce_resolved_ip(url, is_redirect=is_redirect)
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
        response = await self._send(
            method, url, follow_redirects=follow_redirects, headers=headers, **kwargs
        )
        # Silent session refresh: if the response looks unauthenticated and the
        # orchestrator installed a reauth hook, re-establish the session once and
        # replay the original request. The guard stops the hook's own login
        # requests from triggering another reauth (infinite recursion).
        if (
            self.session.reauth is not None
            and not self._reauthing
            and looks_unauthenticated(response.status_code, response.text, self.reauth_markers)
        ):
            self._reauthing = True
            try:
                refreshed = await self.session.reauth()
            finally:
                self._reauthing = False
            if refreshed:
                logger.info("session refreshed after unauthenticated response; retrying %s", url)
                response = await self._send(
                    method, url, follow_redirects=follow_redirects, headers=headers, **kwargs
                )
        response = await self._maybe_evade_block(
            method, url, response, follow_redirects=follow_redirects, headers=headers, kwargs=kwargs
        )
        return response

    async def _maybe_evade_block(
        self,
        method: str,
        url: str,
        response: httpx.Response,
        *,
        follow_redirects: bool,
        headers: dict[str, str] | None,
        kwargs: dict[str, object],
    ) -> httpx.Response:
        """Record the WAF block signal and, if blocked, retry once with a new identity."""
        monitor = getattr(self, "block_monitor", None)
        if monitor is None:  # bare/legacy client without the monitor wired
            return response
        host = urlsplit(url).hostname or ""
        verdict = detect_block(response.status_code, dict(response.headers), _body_of(response))
        monitor.record(host, verdict)
        if not (verdict and verdict.blocked):
            return response
        if verdict.kind == "rate_limit":
            # A 429 means "slow down" — the rate limiter already backs off (AIMD +
            # Retry-After). Retrying with a new identity would only add load.
            return response
        if not getattr(self, "waf_adapt", False) or self._evading:
            logger.debug("WAF block on %s (%s); adaptation off or recursing", url, verdict.reason)
            return response

        logger.info("WAF block on %s: %s — rotating identity and retrying", url, verdict.reason)
        if self.event_bus is not None:
            await self.event_bus.emit(
                "waf.block", url=url, vendor=verdict.vendor, reason=verdict.reason
            )
        self._evading = True
        try:
            lo, hi = self.block_backoff
            if hi > 0:
                await asyncio.sleep(random.uniform(lo, hi))  # brief randomized cool-off
            retried = await self._send(
                method, url, follow_redirects=follow_redirects,
                headers=self._evasion_headers(headers), **kwargs
            )
        finally:
            self._evading = False
        retry_verdict = detect_block(retried.status_code, dict(retried.headers), _body_of(retried))
        monitor.record(host, retry_verdict)
        if not (retry_verdict and retry_verdict.blocked):
            logger.info("evaded WAF block on %s after identity rotation", url)
        return retried

    async def _read_capped(self, response: httpx.Response) -> httpx.Response:
        """Read a streamed body up to ``max_response_bytes``, then stop.

        Guards against a hostile target returning a multi-gigabyte, endless
        chunked, or gzip-bomb body to exhaust memory. ``aiter_bytes`` yields
        *decoded* chunks, so the cap bounds post-decompression size (a small
        compressed bomb is caught too). The accumulated bytes are re-seated on
        ``response._content`` so ``.text``/``.content``/``.json()`` work
        unchanged downstream; over-cap bodies are truncated to the cap.
        """
        cap = self.max_response_bytes
        chunks: list[bytes] = []
        total = 0
        truncated = False
        try:
            async for chunk in response.aiter_bytes():
                chunks.append(chunk)
                total += len(chunk)
                if total > cap:
                    truncated = True
                    break
        except httpx.HTTPError:
            # Stream/decoding failure mid-body: salvage what we read rather than
            # letting a malformed hostile response abort the whole request.
            truncated = True
        # aiter_bytes does not set _content; seat it ourselves (both the normal
        # and the truncated path) so the response is fully readable downstream.
        response._content = b"".join(chunks)[:cap]  # noqa: SLF001
        if truncated:
            with contextlib.suppress(Exception):
                await response.aclose()
            logger.warning(
                "response from %s exceeded the %d-byte cap — body truncated",
                response.url, cap,
            )
        return response

    async def _capped_request(
        self, method: str, url: str, *, headers: dict[str, str], **kwargs: object
    ) -> httpx.Response:
        """Issue a request whose body is read under a hard size cap (hostile-OOM guard)."""
        request = self._client.build_request(method, url, headers=headers, **kwargs)
        response = await self._client.send(request, stream=True)
        return await self._read_capped(response)

    async def _send(
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

        response = await self._capped_request(
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
            response = await self._capped_request(
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
