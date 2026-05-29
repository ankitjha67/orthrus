"""HTTP request smuggling (desync) scanner — timing-based CL.TE / TE.CL probe.

Front-end/back-end disagreement over message framing (Content-Length vs
Transfer-Encoding) lets an attacker smuggle a request prefix past the front-end,
enabling cache poisoning, request hijacking, and auth bypass.

This is the **one** scanner that opens a raw socket instead of using the
scope-enforced HttpClient — because httpx deliberately normalises CL/TE and will
not emit the conflicting framing a smuggling probe requires. Scope is still
enforced: ``ctx.scope.is_allowed()`` must pass before any connection is opened.

Detection is the standard PortSwigger timing technique: a CL.TE (resp. TE.CL)
probe is crafted so a desynced back-end blocks waiting for a chunk that never
arrives. If the probe stalls to the timeout while normal requests are fast, the
endpoint is flagged TENTATIVE for manual confirmation (smuggling truly requires
a front-end/back-end chain, which a single host cannot exhibit — so against one
server this correctly finds nothing).
"""

from __future__ import annotations

import asyncio
import ssl
import time
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger

logger = get_logger("scanner.request-smuggling")

SCANNER_NAME = "request-smuggling"
PROBE_TIMEOUT = 6.0
MAX_HOSTS = 3


def build_baseline(host: str) -> bytes:
    return (f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").encode()


def build_clte_probe(host: str) -> bytes:
    """CL.TE: front-end honours Content-Length, back-end honours chunked -> back-end stalls."""
    body = "1\r\nA\r\nX"
    prefix_len = len("1\r\nA")  # front-end reads this many bytes; back-end then waits for a chunk
    return (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        "Transfer-Encoding: chunked\r\n"
        f"Content-Length: {prefix_len}\r\n"
        f"Connection: close\r\n\r\n{body}"
    ).encode()


def build_tecl_probe(host: str) -> bytes:
    """TE.CL: front-end honours chunked, back-end honours Content-Length -> back-end stalls."""
    body = "0\r\n\r\nX"
    return (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        "Transfer-Encoding: chunked\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n{body}"
    ).encode()


def desync_signal(baseline_time: float, probe_time: float, timeout: float) -> bool:
    """True if the probe stalled (~timeout) while baseline requests were fast."""
    return probe_time >= timeout * 0.9 and baseline_time < timeout * 0.5


def _origin(url: str) -> tuple[str, int, bool] | None:
    parts = urlsplit(url)
    if not parts.hostname:
        return None
    tls = parts.scheme == "https"
    port = parts.port or (443 if tls else 80)
    return parts.hostname, port, tls


@register
class RequestSmugglingScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "request-smuggling"
    min_aggressiveness = Aggressiveness.AGGRESSIVE  # intrusive timing probe via raw socket

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        urls = [ctx.config.target, *[ep.url for ep in ctx.endpoints]]
        for url in urls:
            origin = _origin(url)
            if origin is None:
                continue
            host, port, tls = origin
            if host in seen or len(seen) >= MAX_HOSTS:
                continue
            base_url = f"{'https' if tls else 'http'}://{host}:{port}/"
            if not ctx.scope.is_allowed(base_url):
                continue
            seen.add(host)

            baseline = await self._probe_time(host, port, tls, build_baseline(host), PROBE_TIMEOUT)
            if baseline is None:
                continue
            for label, raw in (
                ("CL.TE", build_clte_probe(host)),
                ("TE.CL", build_tecl_probe(host)),
            ):
                elapsed = await self._probe_time(host, port, tls, raw, PROBE_TIMEOUT)
                if elapsed is None:
                    continue
                if desync_signal(baseline, elapsed, PROBE_TIMEOUT):
                    yield self._finding(base_url, label, baseline, elapsed)
                    break

    def _finding(self, url: str, variant: str, baseline: float, probe: float) -> Finding:
        return Finding(
            vuln_type="request-smuggling",
            title=f"Possible HTTP request smuggling ({variant} desync)",
            severity=Severity.HIGH,
            confidence=Confidence.TENTATIVE,
            url=url,
            description=(
                f"A {variant} probe stalled for {probe:.1f}s while normal requests returned in "
                f"{baseline:.1f}s. This timing gap is the classic signature of a front-end/back-end "
                "disagreement over message framing (Content-Length vs Transfer-Encoding). HTTP "
                "request smuggling enables cache poisoning, request hijacking, and security-control "
                "bypass. Confirm manually (the timing test has false positives on slow/loaded hosts)."
            ),
            remediation=(
                "Make the front-end and back-end agree on framing: normalise/reject ambiguous "
                "requests (both CL and TE, or malformed chunked), prefer HTTP/2 end-to-end, and "
                "disable connection reuse to the back-end where feasible."
            ),
            cwe="CWE-444",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                request_raw=f"{variant} probe (Transfer-Encoding: chunked + Content-Length)",
                notes=f"probe {probe:.1f}s vs baseline {baseline:.1f}s (timeout {PROBE_TIMEOUT}s)",
            ),
        )

    async def _probe_time(
        self, host: str, port: int, tls: bool, raw: bytes, timeout_s: float
    ) -> float | None:
        """Send ``raw`` over a raw socket; return seconds to first response (capped at
        ``timeout_s`` if it stalls), or None on connection failure."""
        ctx_ssl = ssl.create_default_context() if tls else None
        if ctx_ssl is not None:
            ctx_ssl.check_hostname = False
            ctx_ssl.verify_mode = ssl.CERT_NONE
        start = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx_ssl), timeout=timeout_s
            )
        except (TimeoutError, OSError, ssl.SSLError) as exc:
            logger.debug("smuggling connect failed for %s:%s: %s", host, port, exc)
            return None
        try:
            writer.write(raw)
            await asyncio.wait_for(writer.drain(), timeout=timeout_s)
            try:
                await asyncio.wait_for(reader.read(256), timeout=timeout_s)
                elapsed = time.monotonic() - start
            except TimeoutError:
                elapsed = timeout_s
        except (TimeoutError, OSError) as exc:
            logger.debug("smuggling probe error for %s:%s: %s", host, port, exc)
            return None
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except (TimeoutError, OSError):
                pass
        return elapsed


__all__ = [
    "RequestSmugglingScanner",
    "build_baseline",
    "build_clte_probe",
    "build_tecl_probe",
    "desync_signal",
]
