"""Unauthenticated non-HTTP service exposure scanner (native, no external tools).

Web scanners miss data-tier services left open with no authentication - exactly
the Redis-on-:6379 case a live test surfaced. This scanner speaks the services'
own wire protocols over a raw socket and flags ones that answer privileged
commands without auth: an open Redis or Memcached is a direct path to data
theft, cache poisoning, DoS amplification, and frequently RCE.

It probes the *explicit* host:port pairs in scope (the target and any discovered
endpoints with a non-web port) - it does not port-sweep, so it stays inside the
declared engagement. Raw sockets are used by necessity (these aren't HTTP);
scope is checked before every connection. AGGRESSIVE-gated.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from urllib.parse import urlsplit

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger

logger = get_logger("scanner.exposed-services")

SCANNER_NAME = "exposed-services"
PROBE_TIMEOUT = 5.0
MAX_TARGETS = 10
_WEB_PORTS = {80, 443, 8080, 8443}


def redis_unauth(data: bytes) -> bool:
    """True if a Redis PING returned +PONG (or server info) without demanding auth."""
    text = data[:160].decode("latin-1", "ignore")
    upper = text.upper()
    if "NOAUTH" in upper or "WRONGPASS" in upper or "OPERATION NOT PERMITTED" in upper:
        return False  # auth IS required -> secured
    return text.startswith("+PONG") or "redis_version" in text.lower()


def memcached_unauth(data: bytes) -> bool:
    """True if a memcached stats/version command returned data without auth."""
    text = data[:256].decode("latin-1", "ignore")
    return text.startswith(("STAT ", "VERSION "))


# (service, probe bytes, detector, severity, CWE, impact note)
SERVICE_PROBES: tuple[tuple[str, bytes, Callable[[bytes], bool], Severity, str, str], ...] = (
    (
        "Redis",
        b"PING\r\n",
        redis_unauth,
        Severity.CRITICAL,
        "CWE-306",
        "full read/write of all keys, config rewrite, and frequently RCE (e.g. module load "
        "or cron/SSH-key write)",
    ),
    (
        "Memcached",
        b"stats\r\n",
        memcached_unauth,
        Severity.HIGH,
        "CWE-306",
        "disclosure of cached objects (often session tokens) and use as a UDP DDoS amplifier",
    ),
)


def _host_ports(urls: list[str]) -> list[tuple[str, int]]:
    seen: set[tuple[str, int]] = set()
    ordered: list[tuple[str, int]] = []
    for url in urls:
        parts = urlsplit(url if "://" in url else f"//{url}")
        if parts.hostname and parts.port and parts.port not in _WEB_PORTS:
            key = (parts.hostname, parts.port)
            if key not in seen:
                seen.add(key)
                ordered.append(key)
    return ordered


@register
class ServiceExposureScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "exposed-service"
    min_aggressiveness = Aggressiveness.AGGRESSIVE

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        candidates = _host_ports([ctx.config.target, *[ep.url for ep in ctx.endpoints]])[:MAX_TARGETS]
        for host, port in candidates:
            if not ctx.scope.is_allowed(f"http://{host}:{port}/"):
                continue
            for service, probe, detector, severity, cwe, impact in SERVICE_PROBES:
                data = await self._probe(host, port, probe)
                if data is None:
                    break  # port closed / filtered - no service here
                if detector(data):
                    yield self._finding(host, port, service, severity, cwe, impact, data)
                    break

    def _finding(
        self, host: str, port: int, service: str, severity: Severity, cwe: str, impact: str, data: bytes
    ) -> Finding:
        return Finding(
            vuln_type="exposed-service",
            title=f"Unauthenticated {service} exposed on {host}:{port}",
            severity=severity,
            confidence=Confidence.CONFIRMED,
            url=f"{service.lower()}://{host}:{port}",
            description=(
                f"{service} on {host}:{port} answered a privileged command over the network with "
                f"no authentication. An attacker with network access gets {impact}. This service "
                "should never be exposed unauthenticated to untrusted networks."
            ),
            remediation=(
                f"Bind {service} to localhost or a private interface, require authentication "
                "(e.g. Redis 'requirepass' / ACLs, memcached SASL), and firewall the port. "
                "Treat the data as compromised and rotate any secrets it held."
            ),
            cwe=cwe,
            scanner=SCANNER_NAME,
            evidence=Evidence(
                request_raw=f"{service} probe to {host}:{port}",
                matched_at=f"{host}:{port}",
                notes=f"banner: {data[:80].decode('latin-1', 'ignore')!r}",
            ),
        )

    async def _probe(self, host: str, port: int, probe: bytes) -> bytes | None:
        """Open a raw socket, send ``probe``, return the first response bytes (or None)."""
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=PROBE_TIMEOUT
            )
            writer.write(probe)
            await asyncio.wait_for(writer.drain(), timeout=PROBE_TIMEOUT)
            data = await asyncio.wait_for(reader.read(512), timeout=PROBE_TIMEOUT)
            return data or b""
        except (OSError, TimeoutError) as exc:
            logger.debug("service probe %s:%s failed: %s", host, port, exc)
            return None
        finally:
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except (OSError, TimeoutError):
                    pass


__all__ = ["ServiceExposureScanner", "redis_unauth", "memcached_unauth", "SERVICE_PROBES"]
