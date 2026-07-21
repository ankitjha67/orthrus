"""Target preflight: fail in seconds with a diagnosis, not 30 minutes of timeouts.

When a target is unreachable the worst outcome is a scan that grinds through recon
timeouts before giving up with no explanation. This runs a fast, layered probe - DNS
-> TCP -> TLS -> HTTP status line - and turns the first failing layer into a concrete
diagnosis and remedy ("DNS resolves but TCP hangs -> network filtering, pin the IP or
use a proxy"). It uses raw asyncio sockets, not the HTTP client, so it measures the
transport directly and can't itself hang on the same wall the scanner would.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass, field
from time import perf_counter
from urllib.parse import urlsplit

DEFAULT_TIMEOUT = 6.0


@dataclass
class PreflightResult:
    """What each transport layer did for one target."""

    target: str
    host: str = ""
    port: int = 0
    tls_required: bool = True
    dns_ok: bool = False
    resolved_ips: list[str] = field(default_factory=list)
    tcp_ok: bool = False
    tls_ok: bool = False
    http_ok: bool = False
    http_status: int | None = None
    elapsed_ms: float = 0.0
    error: str | None = None

    @property
    def reachable(self) -> bool:
        return self.http_ok


def diagnose(r: PreflightResult) -> str:
    """A human diagnosis + remedy from the probe result (pure, testable)."""
    if not r.dns_ok:
        return (
            "DNS does not resolve. Check the hostname; the domain may be unregistered, parked, "
            "or filtered by your resolver. Try a public resolver, or pin the IP with --resolve."
        )
    ips = ", ".join(r.resolved_ips)
    if not r.tcp_ok:
        return (
            f"DNS resolves ({ips}) but the TCP connection to port {r.port} hangs or is refused. "
            "That is network-level filtering between you and the target - pin the resolved IP or "
            "route through a --proxy (this is the '000 / hung connect' case)."
        )
    if r.tls_required and not r.tls_ok:
        return (
            f"TCP connects to {ips} but the TLS handshake fails. The edge may be blocking your "
            "client by TLS/JA3 fingerprint, or SNI/cert is off. Try a browser-grade TLS client "
            "or a --proxy."
        )
    if not r.http_ok:
        return (
            f"Connected to {ips} but no HTTP status line came back (or a challenge intercepted it "
            "first). The edge is likely serving a bot challenge - supply a harvested session "
            "(--auth-cookie) and a matching --user-agent."
        )
    return f"Reachable: {ips}, HTTP {r.http_status} in {r.elapsed_ms:.0f} ms."


async def _tcp_connect(host: str, port: int, ssl_ctx: ssl.SSLContext | None,
                       timeout: float):  # noqa: ASYNC109 - drives asyncio.wait_for on the connect
    return await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ssl_ctx,
                                server_hostname=host if ssl_ctx else None),
        timeout=timeout,
    )


async def preflight(
    target: str, *, timeout: float = DEFAULT_TIMEOUT,  # noqa: ASYNC109 - bounds each layer's wait_for
) -> PreflightResult:
    """Probe DNS -> TCP -> TLS -> HTTP for ``target`` and record where it fails."""
    start = perf_counter()
    parts = urlsplit(target if "://" in target else f"//{target}", scheme="https")
    host = parts.hostname or target
    tls = parts.scheme != "http"
    port = parts.port or (443 if tls else 80)
    r = PreflightResult(target=target, host=host, port=port, tls_required=tls)

    # DNS
    try:
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout=timeout
        )
        r.resolved_ips = sorted({info[4][0] for info in infos})
        r.dns_ok = bool(r.resolved_ips)
    except (socket.gaierror, OSError, TimeoutError) as exc:
        r.error = f"dns: {type(exc).__name__}"
        r.elapsed_ms = round((perf_counter() - start) * 1000, 1)
        return r

    # TCP (plain) - so a TLS failure is distinguishable from a TCP failure
    writer = None
    try:
        _reader, writer = await _tcp_connect(host, port, None, timeout)
        r.tcp_ok = True
    except (OSError, TimeoutError) as exc:
        r.error = f"tcp: {type(exc).__name__}"
        r.elapsed_ms = round((perf_counter() - start) * 1000, 1)
        return r
    finally:
        if writer is not None:
            writer.close()

    # TLS + HTTP over the right scheme
    ssl_ctx = None
    if tls:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
    conn_writer = None
    try:
        reader, conn_writer = await _tcp_connect(host, port, ssl_ctx, timeout)
        r.tls_ok = tls  # reaching here with an ssl context means the handshake succeeded
        request = (
            f"HEAD {parts.path or '/'} HTTP/1.1\r\nHost: {host}\r\n"
            "User-Agent: orthrus-doctor/1.0\r\nConnection: close\r\nAccept: */*\r\n\r\n"
        )
        conn_writer.write(request.encode())
        await conn_writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        fields = line.split()
        if len(fields) >= 2 and fields[0].upper().startswith(b"HTTP"):
            r.http_status = int(fields[1])
            r.http_ok = True
    except (OSError, ssl.SSLError, TimeoutError, ValueError):
        pass  # tls_ok / http_ok stay False; diagnose() reads the layer that failed
    finally:
        if conn_writer is not None:
            conn_writer.close()

    r.elapsed_ms = round((perf_counter() - start) * 1000, 1)
    return r


__all__ = ["PreflightResult", "preflight", "diagnose", "DEFAULT_TIMEOUT"]
