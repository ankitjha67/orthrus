"""TLS-intercepting proxy - real loopback MITM: terminate TLS, capture plaintext."""

from __future__ import annotations

import asyncio
import ssl
from pathlib import Path

import pytest

pytest.importorskip("httpx")
import httpx  # noqa: E402

from orthrus.core.config import ScopeConfig  # noqa: E402
from orthrus.core.schemas import Endpoint  # noqa: E402
from orthrus.proxy.ca import CertAuthority, generate_ca, leaf_cert  # noqa: E402
from orthrus.proxy.server import ProxyServer  # noqa: E402

SECRET = "SECRET-BODY-4242"


async def _origin_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
    except (TimeoutError, asyncio.IncompleteReadError):
        writer.close()
        return
    body = SECRET.encode()
    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
    await writer.drain()
    writer.close()


def _origin_ssl_ctx(tmp: Path) -> ssl.SSLContext:
    """A self-signed HTTPS origin cert for 127.0.0.1 (its own throwaway CA)."""
    ca_cert, ca_key = generate_ca()
    cert_pem, key_pem = leaf_cert("127.0.0.1", ca_cert, ca_key)
    (tmp / "o.crt").write_bytes(cert_pem)
    (tmp / "o.key").write_bytes(key_pem)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(tmp / "o.crt"), str(tmp / "o.key"))
    return ctx


def test_tls_intercept_terminates_and_captures(tmp_path):
    async def run():
        # 1. a real HTTPS origin on loopback
        origin = await asyncio.start_server(
            _origin_handler, "127.0.0.1", 0, ssl=_origin_ssl_ctx(tmp_path))
        origin_port = origin.sockets[0].getsockname()[1]

        # 2. the ORTHRUS intercepting proxy (127.0.0.1 in scope), trusting nothing upstream
        ca = CertAuthority(tmp_path)
        ca.ensure()
        captured: list[Endpoint] = []
        # allow the origin's ephemeral loopback port (real targets are :443)
        scope = ScopeConfig(domains=[], ip_ranges=["127.0.0.1/32"], ports=[origin_port])
        proxy = ProxyServer(scope, ca=ca, intercept_tls=True, verify_upstream=False,
                            on_capture=captured.append, timeout=10)
        proxy_server = await proxy.serve("127.0.0.1", 0)
        proxy_port = proxy_server.sockets[0].getsockname()[1]

        try:
            # 3. a client that goes THROUGH the proxy and trusts the ORTHRUS CA
            trust = ssl.create_default_context(cafile=str(ca.ca_cert_path))
            async with httpx.AsyncClient(
                proxy=f"http://127.0.0.1:{proxy_port}", verify=trust, timeout=10,
            ) as client:
                resp = await client.get(f"https://127.0.0.1:{origin_port}/betting?id=7")
        finally:
            proxy_server.close()
            origin.close()
            await proxy_server.wait_closed()
            await origin.wait_closed()

        # the proxy decrypted, relayed, and re-encrypted - the client sees the body
        assert resp.status_code == 200
        assert SECRET in resp.text
        # and it captured the plaintext HTTPS request (opaque tunnels can't)
        assert captured, "intercepted request was not captured"
        assert captured[0].url == f"https://127.0.0.1:{origin_port}/betting?id=7"
        assert any(p.name == "id" for p in captured[0].params)

    asyncio.run(run())
