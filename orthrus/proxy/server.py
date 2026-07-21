"""Scope-aware HTTP capturing proxy.

A minimal forward proxy (Burp/ZAP-style, capture-only) whose entire point is to
observe traffic to an *authorized* target and feed the discovered endpoints and
parameters into ORTHRUS's endpoint store - so a manual browse of the app becomes
scanner input. Scope enforcement is load-bearing and deny-by-default: an in-scope
request is forwarded and captured; an out-of-scope one is **blocked** (403)
unless the operator explicitly passes it through (and pass-through traffic is
never captured).

HTTP requests are forwarded via httpx and their responses relayed verbatim.
HTTPS is tunneled (CONNECT) as an opaque relay - no TLS interception, so bodies
aren't captured, only the visited host is noted. The parsing/serialization
helpers are pure and unit-tested; the server itself is exercised over loopback.
"""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from inspect import isawaitable
from urllib.parse import parse_qsl, urlsplit

from orthrus.core.config import ScopeConfig
from orthrus.core.schemas import Endpoint, HttpMethod, Param, ParamLocation
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeValidator

logger = get_logger("proxy")

# Headers that must not be forwarded/relayed as-is (RFC 7230 §6.1 + decode-related).
_HOP_BY_HOP = frozenset({
    "connection", "proxy-connection", "keep-alive", "transfer-encoding",
    "upgrade", "proxy-authorization", "te", "trailer",
})
# On forward, also drop Host so httpx derives it from the target URL (avoids a
# stale/duplicate Host); on the response, drop length/encoding so we can recompute.
_REQUEST_STRIP = _HOP_BY_HOP | {"host"}
_RESPONSE_STRIP = _HOP_BY_HOP | {"content-encoding", "content-length"}
_MAX_BODY = 25 * 1024 * 1024  # 25 MB cap on a single relayed body

CaptureFn = Callable[[Endpoint], Awaitable[None] | None]


@dataclass
class ParsedRequest:
    method: str
    target: str  # absolute-form (http://host/path) or, for CONNECT, authority-form (host:port)
    version: str
    headers: list[tuple[str, str]] = field(default_factory=list)

    def header(self, name: str) -> str | None:
        low = name.lower()
        return next((v for k, v in self.headers if k.lower() == low), None)

    def forward_headers(self) -> dict[str, str]:
        return {k: v for k, v in self.headers if k.lower() not in _REQUEST_STRIP}


def parse_request_head(head: bytes) -> ParsedRequest:
    """Parse a request line + headers (bytes up to, not including, the blank line)."""
    lines = head.split(b"\r\n")
    request_line = lines[0].decode("latin-1")
    parts = request_line.split(" ")
    if len(parts) < 3:
        raise ValueError(f"malformed request line: {request_line!r}")
    method, target, version = parts[0], parts[1], parts[2]
    headers: list[tuple[str, str]] = []
    for raw in lines[1:]:
        if not raw:
            continue
        name, _, value = raw.decode("latin-1").partition(":")
        headers.append((name.strip(), value.strip()))
    return ParsedRequest(method=method, target=target, version=version, headers=headers)


def build_response_head(status: int, reason: str, headers: list[tuple[str, str]]) -> bytes:
    """Serialize a response status line + headers (hop-by-hop already stripped)."""
    out = [f"HTTP/1.1 {status} {reason}"]
    out += [f"{k}: {v}" for k, v in headers]
    return ("\r\n".join(out) + "\r\n\r\n").encode("latin-1")


def extract_endpoint(
    method: str, url: str, *, content_type: str | None = None, body: bytes | None = None,
    response_status: int | None = None,
) -> Endpoint:
    """Build an Endpoint (with query/body params) from an observed request."""
    params: list[Param] = []
    for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        params.append(Param(name=name, location=ParamLocation.QUERY, value=value))
    ctype = (content_type or "").split(";")[0].strip().lower()
    if body and ctype == "application/x-www-form-urlencoded":
        for name, value in parse_qsl(body.decode("latin-1", "ignore"), keep_blank_values=True):
            params.append(Param(name=name, location=ParamLocation.BODY, value=value))
    try:
        http_method = HttpMethod(method.upper())
    except ValueError:
        http_method = HttpMethod.GET
    return Endpoint(
        url=url, method=http_method, params=params,
        response_status=response_status, content_type=content_type, source="proxy",
    )


class ProxyServer:
    """A scope-enforced capturing forward proxy."""

    def __init__(
        self, scope: ScopeConfig, *, on_capture: CaptureFn | None = None,
        allow_out_of_scope: bool = False, timeout: float = 30.0,
        ca: object | None = None, intercept_tls: bool = False,
        verify_upstream: bool = True,
    ) -> None:
        self.validator = ScopeValidator(scope)
        self._on_capture = on_capture
        self.allow_out_of_scope = allow_out_of_scope
        self.timeout = timeout
        # TLS interception (Burp/Caido-style MITM): terminate TLS for in-scope hosts
        # with a leaf cert minted by `ca` (a CertAuthority), so HTTPS bodies are
        # captured instead of opaquely tunneled. Off by default.
        self.ca = ca
        self.intercept_tls = intercept_tls and ca is not None
        self.verify_upstream = verify_upstream
        self.captured = 0
        self.blocked = 0

    async def serve(self, host: str = "127.0.0.1", port: int = 8080) -> asyncio.AbstractServer:
        return await asyncio.start_server(self._handle, host, port)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=self.timeout)
            req = parse_request_head(head[:-4])
            if req.method.upper() == "CONNECT":
                await self._tunnel(req, reader, writer)
            else:
                await self._forward(req, reader, writer)
        except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError) as exc:
            logger.debug("proxy request dropped: %s", exc)
        except Exception as exc:  # noqa: BLE001 - a proxy must never die on one bad connection
            logger.warning("proxy handler error: %s", exc)
        finally:
            writer.close()

    async def _deny(self, writer: asyncio.StreamWriter, url: str, reason: str) -> None:
        self.blocked += 1
        logger.info("blocked out-of-scope %s (%s)", url, reason)
        body = f"ORTHRUS proxy: out of scope ({reason})".encode()
        writer.write(build_response_head(403, "Forbidden",
                                         [("Content-Type", "text/plain"), ("Content-Length", str(len(body)))]) + body)
        await writer.drain()

    async def _forward(self, req: ParsedRequest, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        import httpx

        url = req.target  # proxy clients send absolute-form for http://
        decision = self.validator.check(url)
        if not decision.allowed:
            if not self.allow_out_of_scope:
                await self._deny(writer, url, decision.reason)
                return
        length = int(req.header("content-length") or 0)
        body = await reader.readexactly(min(length, _MAX_BODY)) if length else b""

        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
            upstream = await client.request(req.method, url, headers=req.forward_headers(), content=body)

        content = upstream.content[:_MAX_BODY]
        resp_headers = [(k, v) for k, v in upstream.headers.items() if k.lower() not in _RESPONSE_STRIP]
        resp_headers.append(("Content-Length", str(len(content))))
        writer.write(build_response_head(upstream.status_code, upstream.reason_phrase or "OK", resp_headers))
        writer.write(content)
        await writer.drain()

        if decision.allowed and not decision.third_party:
            await self._capture(extract_endpoint(
                req.method, url, content_type=req.header("content-type"), body=body,
                response_status=upstream.status_code,
            ))

    async def _tunnel(self, req: ParsedRequest, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        host, _, port_s = req.target.partition(":")
        port = int(port_s or 443)
        in_scope = self.validator.host_in_scope(host)
        if not in_scope and not self.allow_out_of_scope:
            await self._deny(writer, f"https://{host}:{port}/", "host not in authorized scope")
            return
        # TLS interception: for in-scope hosts, terminate TLS and capture plaintext.
        if self.intercept_tls and in_scope:
            await self._intercept(host, port, reader, writer)
            return
        try:
            up_reader, up_writer = await asyncio.open_connection(host, port)
        except OSError as exc:
            await self._deny(writer, f"https://{host}:{port}/", f"upstream connect failed: {exc}")
            return
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        if self.validator.host_in_scope(host):
            # We can't see inside TLS; record the visited host as an observed endpoint.
            await self._capture(Endpoint(url=f"https://{host}/", method=HttpMethod.GET, source="proxy-connect"))

        async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            try:
                while (chunk := await src.read(65536)):
                    dst.write(chunk)
                    await dst.drain()
            except OSError:
                pass
            finally:
                dst.close()

        await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer))

    async def _intercept(
        self, host: str, port: int,
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    ) -> None:
        """Terminate TLS for an in-scope host and relay+capture the plaintext HTTP."""
        import httpx

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        # upgrade the client side of the connection to server TLS using our leaf cert.
        ctx = self.ca.ssl_context_for(host)
        loop = asyncio.get_event_loop()
        transport = writer.transport
        protocol = transport.get_protocol()
        try:
            tls_transport = await loop.start_tls(transport, protocol, ctx, server_side=True)
        except (TimeoutError, ssl.SSLError, OSError) as exc:
            logger.debug("TLS interception handshake failed for %s: %s", host, exc)
            return
        writer._transport = tls_transport  # noqa: SLF001 - rebind writes onto the TLS transport

        base = f"https://{host}" + ("" if port == 443 else f":{port}")
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=False, verify=self.verify_upstream,
        ) as client:
            while True:
                try:
                    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=self.timeout)
                except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                    break
                try:
                    req = parse_request_head(head[:-4])
                except ValueError:
                    break
                length = int(req.header("content-length") or 0)
                body = await reader.readexactly(min(length, _MAX_BODY)) if length else b""
                path = req.target if req.target.startswith("/") else "/" + req.target
                url = base + path
                decision = self.validator.check(url)
                if not decision.allowed and not self.allow_out_of_scope:
                    await self._deny(writer, url, decision.reason)
                    continue
                try:
                    upstream = await client.request(
                        req.method, url, headers=req.forward_headers(), content=body)
                except httpx.HTTPError as exc:
                    logger.debug("intercept upstream error for %s: %s", url, exc)
                    break
                content = upstream.content[:_MAX_BODY]
                resp_headers = [(k, v) for k, v in upstream.headers.items()
                                if k.lower() not in _RESPONSE_STRIP]
                resp_headers.append(("Content-Length", str(len(content))))
                writer.write(build_response_head(
                    upstream.status_code, upstream.reason_phrase or "OK", resp_headers))
                writer.write(content)
                await writer.drain()
                if decision.allowed and not decision.third_party:
                    await self._capture(extract_endpoint(
                        req.method, url, content_type=req.header("content-type"),
                        body=body, response_status=upstream.status_code))
                if (req.header("connection") or "").lower() == "close":
                    break

    async def _capture(self, endpoint: Endpoint) -> None:
        self.captured += 1
        if self._on_capture is None:
            return
        result = self._on_capture(endpoint)
        if isawaitable(result):
            await result


__all__ = [
    "ProxyServer", "ParsedRequest",
    "parse_request_head", "build_response_head", "extract_endpoint",
]
