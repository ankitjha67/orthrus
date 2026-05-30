"""gRPC server-reflection scanner.

gRPC services that leave **server reflection** enabled in production hand an
attacker the entire RPC API surface — every service and (via descriptors) every
method and message type — which is exactly what they need to craft calls against
undocumented internal endpoints. This scanner connects to the target over gRPC
and issues a ``ListServices`` reflection request; if the server answers, it
reports the exposed services.

gRPC speaks HTTP/2 with ``application/grpc`` framing, so it needs a real gRPC
client rather than the HTTP stack. The probe is read-only (reflection only) and
scope-checked. No-ops when ``grpcio`` / ``grpcio-reflection`` are not installed
(the optional gRPC extra).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger

try:
    import grpc
    from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc
except ImportError:  # grpcio + grpcio-reflection ship in the optional gRPC extra
    grpc = None  # type: ignore[assignment]

logger = get_logger("scanner.grpc")

SCANNER_NAME = "grpc-reflection"
MAX_TARGETS = 3
PROBE_TIMEOUT = 6.0

# Framework/internal reflection services — exposing these is the *bug*, but the
# attacker-relevant disclosure is the application services they reveal.
_INTERNAL_PREFIXES = ("grpc.reflection.", "grpc.health.", "grpc.channelz.")


def user_services(service_names: list[str]) -> list[str]:
    """Application services from a reflection ListServices result (drop internals)."""
    return [n for n in service_names if not any(n.startswith(p) for p in _INTERNAL_PREFIXES)]


def _targets(ctx: ScanContext) -> list[tuple[str, int, bool]]:
    out: list[tuple[str, int, bool]] = []
    seen: set[tuple[str, int]] = set()
    for url in (ctx.config.target, *[ep.url for ep in ctx.endpoints]):
        parts = urlsplit(url)
        if not parts.hostname:
            continue
        tls = parts.scheme == "https"
        port = parts.port or (443 if tls else 80)
        key = (parts.hostname, port)
        if key in seen:
            continue
        seen.add(key)
        out.append((parts.hostname, port, tls))
    return out[:MAX_TARGETS]


@register
class GrpcReflectionScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "grpc-reflection"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        if grpc is None:
            return
        for host, port, tls in _targets(ctx):
            base = f"{'https' if tls else 'http'}://{host}:{port}/"
            if not ctx.scope.is_allowed(base):
                continue
            services = await self._list_services(host, port, tls)
            if not services:
                continue
            exposed = user_services(services)
            shown = ", ".join(exposed[:20]) if exposed else "(reflection service only)"
            yield Finding(
                vuln_type="grpc-reflection",
                title=f"gRPC server reflection enabled on {host}:{port}",
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                url=base,
                description=(
                    f"The gRPC server answered a reflection ListServices request, exposing its "
                    f"full RPC API surface ({len(exposed)} application service(s): {shown}). "
                    "Reflection lets an attacker enumerate every service, method, and message type "
                    "and call undocumented/internal RPCs directly."
                ),
                remediation=(
                    "Disable gRPC server reflection in production (register it only in dev), and "
                    "enforce authentication/authorization on every method."
                ),
                cwe="CWE-200",
                scanner=SCANNER_NAME,
                evidence=Evidence(
                    matched_at=f"{host}:{port}",
                    notes=f"reflection ListServices returned: {shown}",
                ),
            )

    async def _list_services(self, host: str, port: int, tls: bool) -> list[str] | None:
        target = f"{host}:{port}"
        channel = (
            grpc.aio.secure_channel(target, grpc.ssl_channel_credentials())
            if tls
            else grpc.aio.insecure_channel(target)
        )
        try:
            return await asyncio.wait_for(self._reflect(channel), timeout=PROBE_TIMEOUT)
        except Exception as exc:  # noqa: BLE001 - any gRPC/timeout error = not reflectable
            logger.debug("grpc reflection failed for %s: %s", target, exc)
            return None
        finally:
            await channel.close()

    async def _reflect(self, channel: object) -> list[str]:
        stub = reflection_pb2_grpc.ServerReflectionStub(channel)

        async def request_iter() -> AsyncIterator[object]:
            yield reflection_pb2.ServerReflectionRequest(list_services="")

        services: list[str] = []
        async for resp in stub.ServerReflectionInfo(request_iter()):
            if resp.HasField("list_services_response"):
                services = [s.name for s in resp.list_services_response.service]
            break
        return services


__all__ = ["GrpcReflectionScanner", "user_services"]
