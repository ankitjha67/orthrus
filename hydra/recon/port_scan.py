"""Port scanning via Nmap (PRD §5.4).

Wraps python-nmap (the [recon] extra) and the system ``nmap`` binary. Both are
optional: if either is missing, the module degrades to no results. The pure
``parse_nmap`` converts python-nmap's result dict into (host, open-port) tuples
and is unit-tested. Runs only when explicitly requested (intrusive).
"""

from __future__ import annotations

import asyncio
import shutil
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from hydra.core import schemas
from hydra.core.context import ScanContext
from hydra.recon.base import BaseRecon
from hydra.utils.logger import get_logger

logger = get_logger("recon.ports")

DEFAULT_PORTS = "1-1000"


def parse_nmap(scan_result: dict) -> list[tuple[str, list[int]]]:
    """Convert nmap.PortScanner().scan() result into (host, [open ports])."""
    hosts: list[tuple[str, list[int]]] = []
    for host, data in scan_result.get("scan", {}).items():
        ports = []
        for proto in ("tcp", "udp"):
            for port, info in data.get(proto, {}).items():
                if info.get("state") == "open":
                    ports.append(int(port))
        if ports:
            hosts.append((host, sorted(ports)))
    return hosts


class PortScan(BaseRecon):
    name = "port-scan"

    def applicable(self, ctx: ScanContext) -> bool:
        if shutil.which("nmap") is None:
            logger.info("nmap binary not found; skipping port scan")
            return False
        try:
            import nmap  # noqa: F401
        except ImportError:
            logger.info("python-nmap not installed ([recon] extra); skipping port scan")
            return False
        return True

    async def discover(self, ctx: ScanContext) -> AsyncIterator[schemas.Asset]:
        import nmap

        host = (
            urlsplit(ctx.config.target if "://" in ctx.config.target else f"//{ctx.config.target}")
            .hostname or ctx.config.target
        )
        ports = (
            ",".join(str(p) for p in ctx.config.scope.ports)
            if ctx.config.scope.ports
            else DEFAULT_PORTS
        )

        def _run() -> dict:
            scanner = nmap.PortScanner()
            return scanner.scan(host, ports, arguments="-sV -T4")

        try:
            result = await asyncio.to_thread(_run)
        except Exception as exc:
            logger.debug("nmap scan failed for %s: %s", host, exc)
            return

        for found_host, open_ports in parse_nmap(result):
            logger.info("open ports on %s: %s", found_host, open_ports)
            yield schemas.Asset(
                fqdn=found_host, ports=open_ports, discovery_method="port-scan"
            )


__all__ = ["PortScan", "parse_nmap"]
