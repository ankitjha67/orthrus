"""Example plugin (PRD §13) — a template for custom scanners.

Demonstrates the plugin interface: subclass BaseScanner, decorate with
``@register`` from the scanner registry, and the loader picks it up at startup.
This benign example raises an INFO finding when a server reveals its software
via the Server header. Copy this file to build your own, or drop modules into
``$ORTHRUS_PLUGINS_DIR``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register


@register
class ExampleServerBannerScanner(BaseScanner):
    name = "example-server-banner"
    vuln_type = "example"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        for ep in ctx.endpoints:
            server = ep.response_headers.get("server") or ep.response_headers.get("Server")
            if not server or server in seen:
                continue
            seen.add(server)
            yield Finding(
                vuln_type="example",
                title=f"Server banner disclosed: {server}",
                severity=Severity.INFO,
                confidence=Confidence.FIRM,
                url=ep.url,
                description=f"Example plugin: the Server header advertises '{server}'.",
                remediation="Suppress or genericize the Server header.",
                cwe="CWE-200",
                scanner=self.name,
                evidence=Evidence(matched_at=server),
            )


__all__ = ["ExampleServerBannerScanner"]
