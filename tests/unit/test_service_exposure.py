"""Unauthenticated service-exposure scanner (native Redis/Memcached probes)."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Severity
from orthrus.scanners.service_exposure import (
    ServiceExposureScanner,
    _host_ports,
    memcached_unauth,
    redis_unauth,
)


# ----------------------------------------------------------------- detectors
def test_redis_unauth() -> None:
    assert redis_unauth(b"+PONG\r\n") is True
    assert redis_unauth(b"$1234\r\n# Server\r\nredis_version:7.0.0\r\n") is True
    assert redis_unauth(b"-NOAUTH Authentication required.\r\n") is False  # secured
    assert redis_unauth(b"HTTP/1.1 400 Bad Request\r\n") is False  # web server, not redis


def test_memcached_unauth() -> None:
    assert memcached_unauth(b"STAT pid 12\r\nSTAT uptime 99\r\nEND\r\n") is True
    assert memcached_unauth(b"VERSION 1.6.9\r\n") is True
    assert memcached_unauth(b"ERROR\r\n") is False


def test_host_ports_extracts_non_web_ports() -> None:
    pairs = _host_ports(
        ["http://h:6379", "pentest-ground.com:11211", "https://h:443", "https://h/path", "http://h:80"]
    )
    assert ("h", 6379) in pairs
    assert ("pentest-ground.com", 11211) in pairs
    assert ("h", 443) not in pairs  # web port skipped
    assert all(p != 80 for _, p in pairs)


# ----------------------------------------------------------------- scanner
def _ctx(target: str, http_ok: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(target=target),
        endpoints=[],
        scope=SimpleNamespace(is_allowed=lambda _u: True),
    )


class _RedisScanner(ServiceExposureScanner):
    async def _probe(self, host, port, probe):  # type: ignore[override]
        return b"+PONG\r\n"


class _SecuredScanner(ServiceExposureScanner):
    async def _probe(self, host, port, probe):  # type: ignore[override]
        return b"-NOAUTH Authentication required.\r\n"


class _ClosedScanner(ServiceExposureScanner):
    async def _probe(self, host, port, probe):  # type: ignore[override]
        return None


async def test_scanner_flags_unauth_redis() -> None:
    findings = [f async for f in _RedisScanner().scan(_ctx("http://target:6379"))]
    svc = [f for f in findings if f.vuln_type == "exposed-service"]
    assert len(svc) == 1
    assert svc[0].severity == Severity.CRITICAL
    assert svc[0].cwe == "CWE-306"
    assert "Redis" in svc[0].title


async def test_scanner_quiet_when_secured() -> None:
    findings = [f async for f in _SecuredScanner().scan(_ctx("http://target:6379"))]
    assert [f for f in findings if f.vuln_type == "exposed-service"] == []


async def test_scanner_quiet_when_port_closed() -> None:
    findings = [f async for f in _ClosedScanner().scan(_ctx("http://target:6379"))]
    assert findings == []


async def test_scanner_ignores_web_ports() -> None:
    # Port 443 is a web port -> never probed, even by the redis-answering stub.
    findings = [f async for f in _RedisScanner().scan(_ctx("https://target"))]
    assert findings == []
