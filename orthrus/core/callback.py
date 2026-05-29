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

import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from orthrus.utils.logger import get_logger

logger = get_logger("callback")


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


__all__ = ["CallbackClient", "LocalCallbackServer", "Interaction"]
