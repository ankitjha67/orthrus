"""Out-of-band (OOB) interaction server for blind/SSRF detection (PRD §7.2).

The PRD's production path is Interactsh; this is the self-hosted Python fallback:
a small threaded HTTP listener that mints a unique token per payload and records
any interaction (the target/victim calling back) against that token. Scanners
inject the per-token URL and poll for hits.

Note: bound to 127.0.0.1 by default, so only same-host targets can reach it.
External engagements should point --callback at a reachable host / Interactsh.
The architecture (CallbackClient) lets an Interactsh client drop in later.
"""

from __future__ import annotations

import asyncio
import base64
import json
import secrets
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from orthrus.utils.logger import get_logger

logger = get_logger("callback")

# xid-compatible alphabet for Interactsh correlation IDs / payload subdomains.
_XID_ALPHABET = "0123456789abcdefghijklmnopqrstuv"


@dataclass
class Interaction:
    token: str
    protocol: str
    source_ip: str
    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    timestamp: float = field(default_factory=time.time)


class CallbackClient(ABC):
    @property
    @abstractmethod
    def base_url(self) -> str: ...

    @abstractmethod
    def new_token(self) -> tuple[str, str]:
        """Return (token, callback_url) for a single payload."""

    @abstractmethod
    async def poll(self, token: str) -> list[Interaction]:
        """Return interactions recorded for ``token`` so far."""

    async def start(self) -> None: ...

    async def stop(self) -> None: ...


def _make_handler(record):  # type: ignore[no-untyped-def]
    class _Handler(BaseHTTPRequestHandler):
        def _handle(self) -> None:
            token = self.path.strip("/").split("/", 1)[0].split("?", 1)[0]
            try:
                length = int(self.headers.get("Content-Length", "0") or 0)
            except ValueError:
                length = 0
            body = self.rfile.read(length).decode("utf-8", "ignore") if length else ""
            record(
                Interaction(
                    token=token,
                    protocol="http",
                    source_ip=self.client_address[0],
                    method=self.command,
                    path=self.path,
                    headers={k: v for k, v in self.headers.items()},
                    body=body,
                )
            )
            payload = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        do_GET = _handle  # noqa: N815
        do_POST = _handle  # noqa: N815
        do_PUT = _handle  # noqa: N815
        do_HEAD = _handle  # noqa: N815

        def log_message(self, *args: object) -> None:
            pass

    return _Handler


class LocalCallbackServer(CallbackClient):
    def __init__(
        self,
        bind_host: str = "127.0.0.1",
        port: int = 0,
        advertise_host: str | None = None,
    ) -> None:
        self._bind_host = bind_host
        self._port = port
        self._advertise_host = advertise_host or bind_host
        self._store: dict[str, list[Interaction]] = {}
        self._lock = threading.Lock()
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        return f"http://{self._advertise_host}:{self._port}"

    def new_token(self) -> tuple[str, str]:
        token = uuid.uuid4().hex[:16]
        return token, f"{self.base_url}/{token}"

    def _record(self, interaction: Interaction) -> None:
        with self._lock:
            self._store.setdefault(interaction.token, []).append(interaction)

    async def poll(self, token: str) -> list[Interaction]:
        with self._lock:
            return list(self._store.get(token, []))

    async def start(self) -> None:
        handler = _make_handler(self._record)
        self._httpd = ThreadingHTTPServer((self._bind_host, self._port), handler)
        self._port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        logger.info("callback server listening on %s", self.base_url)

    async def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None


def _rand_id(length: int) -> str:
    return "".join(secrets.choice(_XID_ALPHABET) for _ in range(length))


class InteractshCallbackClient(CallbackClient):
    """Real Interactsh OOB collaborator client (ProjectDiscovery protocol).

    Registers an RSA public key with a public (oast.fun/oast.pro/...) or
    self-hosted Interactsh server, mints a unique subdomain per payload, then
    polls the server and decrypts the recorded interactions (DNS / HTTP / SMTP
    callbacks). Each poll returns an AES key wrapped with our public key
    (RSA-OAEP, SHA-256); the interactions are AES-128-CFB ciphertext.

    Unlike :class:`LocalCallbackServer`, this reaches a real internet-resolvable
    collaborator, so it detects blind/OOB vulns on targets that cannot route
    back to the operator's host. It needs network egress to the server; when
    registration fails the orchestrator falls back to the local listener.

    Polling does not flow through the scope-enforced HttpClient by design: the
    collaborator is operator infrastructure, not the engagement target.
    """

    DEFAULT_SERVERS = ("oast.fun", "oast.pro", "oast.site", "oast.online", "oast.me")

    def __init__(
        self,
        server: str | None = None,
        token: str | None = None,
        *,
        timeout: float = 20.0,
    ) -> None:
        self._servers = [server] if server else list(self.DEFAULT_SERVERS)
        self._auth_token = token  # optional self-hosted server auth (-t)
        self._timeout = timeout
        self._domain = ""
        self._correlation_id = _rand_id(20)
        self._secret = str(uuid.uuid4())
        self._private_key = None  # type: ignore[var-annotated]
        self._registered = False
        self._store: dict[str, list[Interaction]] = {}
        self._lock = asyncio.Lock()
        self._client = None  # type: ignore[var-annotated]

    @property
    def base_url(self) -> str:
        return f"https://{self._domain}"

    def new_token(self) -> tuple[str, str]:
        # token == the 33-char subdomain label the server reports as unique-id.
        host = f"{self._correlation_id}{_rand_id(13)}"
        return host, f"https://{host}.{self._domain}"

    async def start(self) -> None:
        import httpx
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_pem = self._private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pub_b64 = base64.b64encode(pub_pem).decode()
        self._client = httpx.AsyncClient(timeout=self._timeout)
        payload = {
            "public-key": pub_b64,
            "secret-key": self._secret,
            "correlation-id": self._correlation_id,
        }
        headers = {"Content-Type": "application/json"}
        if self._auth_token:
            headers["Authorization"] = self._auth_token
        for server in self._servers:
            try:
                resp = await self._client.post(
                    f"https://{server}/register", json=payload, headers=headers
                )
            except httpx.HTTPError as exc:
                logger.debug("interactsh register failed for %s: %s", server, exc)
                continue
            if resp.status_code == 200:
                self._domain = server
                self._registered = True
                logger.info("registered with Interactsh collaborator %s", server)
                return
            logger.debug("interactsh %s register -> HTTP %s", server, resp.status_code)
        await self._client.aclose()
        self._client = None
        raise RuntimeError("could not register with any Interactsh server")

    @staticmethod
    def _aes_decrypt(key: bytes, ciphertext: bytes) -> str:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        iv, body = ciphertext[:16], ciphertext[16:]
        decryptor = Cipher(algorithms.AES(key), modes.CFB(iv)).decryptor()
        return (decryptor.update(body) + decryptor.finalize()).decode("utf-8", "ignore")

    def _decrypt_aes_key(self, wrapped_b64: str) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        return self._private_key.decrypt(  # type: ignore[union-attr]
            base64.b64decode(wrapped_b64),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def _ingest(self, body: dict) -> None:
        data = body.get("data") or []
        wrapped = body.get("aes_key")
        if not data or not wrapped:
            return
        aes_key = self._decrypt_aes_key(wrapped)
        for item in data:
            try:
                obj = json.loads(self._aes_decrypt(aes_key, base64.b64decode(item)))
            except (ValueError, TypeError):
                continue
            unique_id = obj.get("unique-id") or obj.get("full-id") or ""
            self._store.setdefault(unique_id, []).append(
                Interaction(
                    token=unique_id,
                    protocol=obj.get("protocol", "dns"),
                    source_ip=obj.get("remote-address", ""),
                    method=obj.get("q-type", ""),
                    path=obj.get("full-id", ""),
                    body=obj.get("raw-request", ""),
                )
            )

    async def _drain(self) -> None:
        import httpx

        if not self._registered or self._client is None:
            return
        headers = {"Authorization": self._auth_token} if self._auth_token else {}
        try:
            resp = await self._client.get(
                f"https://{self._domain}/poll",
                params={"id": self._correlation_id, "secret": self._secret},
                headers=headers,
            )
        except httpx.HTTPError as exc:
            logger.debug("interactsh poll failed: %s", exc)
            return
        if resp.status_code != 200:
            return
        try:
            self._ingest(resp.json())
        except (ValueError, KeyError) as exc:
            logger.debug("interactsh poll decode failed: %s", exc)

    async def poll(self, token: str) -> list[Interaction]:
        async with self._lock:
            await self._drain()
            hits = list(self._store.get(token, []))
            if not hits:
                # Tolerate unique-id vs full-id representation differences.
                for key, items in self._store.items():
                    if key and (token in key or key in token):
                        hits.extend(items)
            return hits

    async def stop(self) -> None:
        import httpx

        if self._client is None:
            return
        try:
            await self._client.post(
                f"https://{self._domain}/deregister",
                json={"correlation-id": self._correlation_id, "secret-key": self._secret},
                headers={"Authorization": self._auth_token} if self._auth_token else {},
            )
        except httpx.HTTPError:
            pass
        await self._client.aclose()
        self._client = None


__all__ = [
    "CallbackClient",
    "Interaction",
    "InteractshCallbackClient",
    "LocalCallbackServer",
]
