"""Target preflight: layered DNS/TCP/TLS/HTTP probe + diagnosis."""

from __future__ import annotations

import asyncio

from orthrus.core.preflight import PreflightResult, diagnose, preflight


# ------------------------------------------------------------ diagnose (pure)
def _r(**kw) -> PreflightResult:
    base = {"target": "https://t", "host": "t", "port": 443, "resolved_ips": ["93.1.2.3"]}
    base.update(kw)
    return PreflightResult(**base)


def test_diagnose_no_dns():
    msg = diagnose(_r(dns_ok=False, resolved_ips=[]))
    assert "DNS does not resolve" in msg


def test_diagnose_tcp_hang():
    msg = diagnose(_r(dns_ok=True, tcp_ok=False))
    assert "TCP connection" in msg and "network-level filtering" in msg


def test_diagnose_tls_block():
    msg = diagnose(_r(dns_ok=True, tcp_ok=True, tls_required=True, tls_ok=False))
    assert "TLS handshake fails" in msg and "fingerprint" in msg


def test_diagnose_http_challenge():
    msg = diagnose(_r(dns_ok=True, tcp_ok=True, tls_ok=True, http_ok=False))
    assert "no HTTP status line" in msg and "challenge" in msg


def test_diagnose_reachable():
    msg = diagnose(_r(dns_ok=True, tcp_ok=True, tls_ok=True, http_ok=True,
                      http_status=200, elapsed_ms=42.0))
    assert msg.startswith("Reachable") and "200" in msg


# ------------------------------------------------------------ real-socket probe
def test_preflight_tcp_refused_on_closed_port():
    # 127.0.0.1 resolves; port 1 is closed -> DNS ok, TCP refused, honest diagnosis.
    r = asyncio.run(preflight("http://127.0.0.1:1", timeout=3.0))
    assert r.dns_ok is True and r.tcp_ok is False
    assert "network-level filtering" in diagnose(r) or "refused" in (r.error or "")


def test_preflight_full_path_against_local_server():
    async def run() -> PreflightResult:
        async def handle(reader, writer):
            await reader.readline()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            return await preflight(f"http://127.0.0.1:{port}", timeout=3.0)
        finally:
            server.close()
            await server.wait_closed()

    r = asyncio.run(run())
    assert r.dns_ok and r.tcp_ok and r.http_ok and r.http_status == 200
    assert r.reachable and diagnose(r).startswith("Reachable")
