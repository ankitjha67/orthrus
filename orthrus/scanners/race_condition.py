"""Race condition / TOCTOU scanner — single-packet / last-byte synchronization.

Many state-changing actions guard a limit with a non-atomic *check-then-commit*
(``if coupon_unused: redeem()``). Between the check and the commit there is a
window; land enough requests in it simultaneously and several slip past a guard
that should admit only one — redeeming a one-shot coupon N times, overdrawing a
balance, over-voting, bypassing a signup cap (CWE-362).

The hard part is landing the requests in the *same* window despite network
jitter. The primary detector uses **last-byte synchronization** (James Kettle's
technique): open one connection per request, send every byte *except the last*,
let them buffer server-side, then release the final byte on every connection
together — so the server sees the complete requests almost simultaneously (the
HTTP/1.1 analogue of the HTTP/2 single-packet attack). This needs byte-level
send control, so — like the smuggling scanner — it uses a **raw socket** rather
than the HttpClient. Scope is still enforced before any connection is opened.

The synchronized oracle is conservative: a burst is flagged **only** when ≥2
requests were accepted (2xx) while ≥1 was rejected by a limit (409/403/410/422/…).
The rejection proves a limit exists; ≥2 accepts prove it was bypassed concurrently.
An atomically-locked endpoint returns exactly one 2xx (correctly **not** flagged);
pure rate-limit throttling (429/503) is excluded. Where a raw socket can't be
opened, the scanner falls back to the older httpx partial-success heuristic
(TENTATIVE).
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import (
    Aggressiveness,
    Confidence,
    Evidence,
    Finding,
    HttpMethod,
    ParamLocation,
    Severity,
)
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.race-condition")

SCANNER_NAME = "race-condition"
BURST = 8            # httpx fallback burst size
SYNC_BURST = 20      # synchronized (last-byte) burst size
MAX_ENDPOINTS = 6    # cap how many candidates we burst (intrusive)
CONNECT_TIMEOUT = 8.0
READ_TIMEOUT = 8.0

# Statuses that signal a *limit/guard* rejected the request (proving a limit
# exists). Deliberately excludes 429/503 — benign rate limiting / overload.
LIMIT_REJECT = {400, 402, 403, 404, 405, 409, 410, 422, 423}

TRANSACTIONAL_HINTS = {
    "coupon", "redeem", "transfer", "vote", "amount", "qty", "quantity",
    "purchase", "buy", "balance", "gift", "promo", "voucher", "withdraw",
    "apply", "claim", "order", "checkout", "credit", "points",
}

# State-changing actions whose *path* implies a consumable limit / one-shot.
RACE_KEYWORDS = (
    "redeem", "coupon", "voucher", "gift", "promo", "discount", "claim", "apply",
    "withdraw", "transfer", "balance", "topup", "payout", "vote", "like", "follow",
    "purchase", "order", "checkout", "buy", "register", "signup", "invite",
    "referral", "points", "reward", "credit", "ticket", "reserve", "book",
)


def race_signal(success_count: int, total: int) -> bool:
    """Partial success across a concurrent burst => contention on a once-only op."""
    return 1 < success_count < total


def parse_status(response: bytes) -> int | None:
    """Extract the HTTP status code from a raw response (``HTTP/1.1 200 OK``)."""
    try:
        return int(response.split(b"\r\n", 1)[0].split(b" ", 2)[1])
    except (IndexError, ValueError):
        return None


@dataclass
class RaceVerdict:
    accepts: int
    rejects: int
    statuses: list[int] = field(default_factory=list)
    raced: bool = False
    reason: str = ""


def classify_race(responses: list[bytes]) -> RaceVerdict:
    """Limit-overrun oracle: raced iff ≥2 accepted (2xx) while ≥1 limit-rejected.

    An atomic endpoint yields exactly one accept; an unlimited endpoint yields all
    accepts and no limit-rejects; neither is flagged.
    """
    statuses = [s for r in responses if (s := parse_status(r)) is not None]
    accepts = sum(1 for s in statuses if 200 <= s < 300)
    rejects = sum(1 for s in statuses if s in LIMIT_REJECT)
    raced = accepts >= 2 and rejects >= 1
    reason = (
        f"{accepts} of {len(statuses)} synchronized requests were accepted past a limit that "
        f"rejected {rejects} of them — a non-atomic check-then-commit window"
        if raced else "no limit overrun observed"
    )
    return RaceVerdict(accepts, rejects, statuses, raced, reason)


def is_race_candidate(method: str, url: str) -> bool:
    """A state-changing request, or any request whose path hints at a limit."""
    if any(kw in urlsplit(url).path.lower() for kw in RACE_KEYWORDS):
        return True
    return method.upper() in {"POST", "PUT", "PATCH", "DELETE"}


def build_raw_request(method: str, host: str, path: str, body: str = "") -> bytes:
    """Assemble a minimal raw HTTP/1.1 request. The final byte is the sync point."""
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}",
             "User-Agent: orthrus-race/1.0", "Accept: */*"]
    if body:
        lines.append("Content-Type: application/x-www-form-urlencoded")
        lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    lines.append("")
    lines.append(body)
    return "\r\n".join(lines).encode()


def _origin(url: str) -> tuple[str, int, bool] | None:
    parts = urlsplit(url)
    if not parts.hostname:
        return None
    tls = parts.scheme == "https"
    return parts.hostname, (parts.port or (443 if tls else 80)), tls


def _path_of(url: str) -> str:
    parts = urlsplit(url)
    return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


def _ssl_ctx(tls: bool) -> ssl.SSLContext | None:
    if not tls:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def last_byte_burst(
    host: str, port: int, tls: bool, raw: bytes, count: int,
    *, connect_timeout: float = CONNECT_TIMEOUT, read_timeout: float = READ_TIMEOUT,
) -> list[bytes]:
    """Send ``count`` copies of ``raw`` with last-byte synchronization.

    Opens ``count`` connections, writes all but the final byte on each, pauses so
    every server buffers the near-complete request, then releases the final byte
    on every connection together. Returns each connection's raw response bytes.
    """
    ctx_ssl = _ssl_ctx(tls)
    conns = []
    for _ in range(count):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx_ssl), timeout=connect_timeout
            )
            conns.append((reader, writer))
        except (TimeoutError, OSError, ssl.SSLError) as exc:
            logger.debug("race connect failed for %s:%s: %s", host, port, exc)
    if len(conns) < 2:
        for _, writer in conns:
            writer.close()
        return []

    head, last = raw[:-1], raw[-1:]
    try:
        for _, writer in conns:
            writer.write(head)
        await asyncio.gather(*(writer.drain() for _, writer in conns), return_exceptions=True)
        await asyncio.sleep(0.15)  # let every server buffer the near-complete request
        for _, writer in conns:
            writer.write(last)  # release the synchronization byte on all connections
        await asyncio.gather(*(writer.drain() for _, writer in conns), return_exceptions=True)

        async def _read(reader) -> bytes:  # type: ignore[no-untyped-def]
            try:
                return await asyncio.wait_for(reader.read(8192), timeout=read_timeout)
            except (TimeoutError, OSError, ssl.SSLError):
                return b""

        responses = await asyncio.gather(*(_read(r) for r, _ in conns))
    finally:
        for _, writer in conns:
            with contextlib.suppress(Exception):
                writer.close()
    return [r for r in responses if r]


@register
class RaceConditionScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "race-condition"
    min_aggressiveness = Aggressiveness.AGGRESSIVE  # fires bursts of state-changing requests

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        tested = 0
        seen: set[tuple[str, str]] = set()
        for ep in ctx.endpoints:
            if tested >= MAX_ENDPOINTS:
                break
            method = ep.method.value if isinstance(ep.method, HttpMethod) else str(ep.method)
            if not is_race_candidate(method, ep.url):
                continue
            key = (method, ep.url)
            if key in seen or not ctx.scope.is_allowed(ep.url):
                continue
            seen.add(key)
            origin = _origin(ep.url)
            if origin is None:
                continue
            host, port, tls = origin

            body = ""
            if method in {"POST", "PUT", "PATCH"}:
                form = {
                    p.name: (p.value or "1")
                    for p in ep.params
                    if p.location in (ParamLocation.BODY, ParamLocation.QUERY, ParamLocation.JSON)
                }
                body = urlencode(form) if form else ""
            raw = build_raw_request(method, host, _path_of(ep.url), body)

            # Primary: last-byte-synchronized burst with a precise overrun oracle.
            responses = await last_byte_burst(host, port, tls, raw, SYNC_BURST)
            if len(responses) >= 2:
                tested += 1
                verdict = classify_race(responses)
                if verdict.raced:
                    yield self._sync_finding(ep.url, method, verdict)
                continue

            # Fallback: raw socket unavailable — older httpx partial-success heuristic.
            if ep.method == HttpMethod.POST and ep.source == "form":
                data = {
                    p.name: (p.value or "1")
                    for p in ep.params if p.location == ParamLocation.BODY
                }
                if not data:
                    continue
                tested += 1
                statuses = await self._burst(ctx, ep.url, data)
                success = sum(1 for s in statuses if 200 <= s < 300)
                if race_signal(success, len(statuses)):
                    yield self._heuristic_finding(ep.url, statuses, success)

    def _sync_finding(self, url: str, method: str, verdict: RaceVerdict) -> Finding:
        return Finding(
            vuln_type="race-condition",
            title="Race condition (limit overrun via synchronized requests)",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            url=url,
            description=(
                f"A burst of {SYNC_BURST} {method} requests, landed in the same window via last-byte "
                f"synchronization, was handled non-atomically: {verdict.reason}. The endpoint guards "
                "a limit with a check-then-commit that has no lock, so concurrent requests pass the "
                "check before any commits — letting an attacker exceed a one-shot/quota limit (e.g. "
                "redeem a coupon repeatedly, overdraw a balance, bypass a signup cap)."
            ),
            remediation=(
                "Make the check and the state change atomic: a transaction with the right isolation "
                "(SELECT ... FOR UPDATE / optimistic locking via a version column), a unique "
                "constraint on the consumable resource, or an atomic decrement — never a "
                "read-modify-write across separate statements. Idempotency keys help too."
            ),
            cwe="CWE-362",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                request_raw=f"{SYNC_BURST}× synchronized {method} {url} (last-byte sync)",
                notes=(
                    f"accepted={verdict.accepts} limit-rejected={verdict.rejects} "
                    f"statuses={verdict.statuses}"
                ),
            ),
        )

    def _heuristic_finding(self, url: str, statuses: list[int], success: int) -> Finding:
        return Finding(
            vuln_type="race-condition",
            title=f"Possible race condition (TOCTOU) at {url}",
            severity=Severity.MEDIUM,
            confidence=Confidence.TENTATIVE,
            url=url,
            description=(
                f"A burst of {len(statuses)} concurrent requests produced {success} "
                "successes — a once-only operation appears to be granted multiple times "
                "under concurrency. Manual verification required (timing-dependent)."
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


__all__ = [
    "RaceConditionScanner",
    "race_signal",
    "classify_race",
    "RaceVerdict",
    "parse_status",
    "build_raw_request",
    "is_race_candidate",
    "last_byte_burst",
]
