"""External-tool recon adapters (PRD §7.2, Appendix A).

Wrap best-of-breed subdomain enumerators (subfinder, amass) behind the same
:class:`ReconAdapter` interface as the pure-Python sources. Each runs the binary
per in-scope domain, parses its line output into subdomain assets, and self-skips
when the tool isn't installed - so the operator gets more coverage by installing
tools, without any pipeline change. Parsing is pure and unit-tested; the
subprocess run is the only part that needs the binary.
"""

from __future__ import annotations

import asyncio

from orthrus.recon_engine.base import DiscoveredAsset, ReconAdapter, ReconScope, register_recon
from orthrus.utils.logger import get_logger

logger = get_logger("recon_engine.tools")


def _in_domain(name: str, domain: str) -> bool:
    name = name.strip().lstrip("*.").lower().rstrip(".")
    return bool(name) and (name == domain or name.endswith("." + domain))


def parse_subdomain_lines(stdout: str, domain: str, source: str) -> list[DiscoveredAsset]:
    """One host per line → in-domain subdomain assets (shared by line-based tools)."""
    out: list[DiscoveredAsset] = []
    seen: set[str] = set()
    for raw in (stdout or "").splitlines():
        host = raw.strip().lstrip("*.").lower().rstrip(".")
        if host and host not in seen and _in_domain(host, domain):
            seen.add(host)
            out.append(DiscoveredAsset("subdomain", host, source))
    return out


class ExternalReconAdapter(ReconAdapter):
    """Base for a subdomain enumerator invoked once per in-scope domain."""

    default_timeout: float = 300.0

    def build_command(self, domain: str) -> list[str]:
        raise NotImplementedError

    async def discover(self, scope: ReconScope) -> list[DiscoveredAsset]:
        found: list[DiscoveredAsset] = []
        for domain in scope.domains:
            stdout = await self._exec(self.build_command(domain))
            if stdout:
                found.extend(parse_subdomain_lines(stdout, domain, self.name))
        return found

    async def _exec(self, cmd: list[str]) -> str | None:
        proc: asyncio.subprocess.Process | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out, _err = await asyncio.wait_for(proc.communicate(), timeout=self.default_timeout)
            return out.decode("utf-8", "ignore")
        except (FileNotFoundError, OSError, ValueError) as exc:
            logger.warning("recon tool '%s' could not start: %s", self.name, exc)
            return None
        except TimeoutError:
            logger.warning("recon tool '%s' timed out", self.name)
            if proc is not None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            return None


@register_recon
class SubfinderAdapter(ExternalReconAdapter):
    name = "subfinder"
    binary = "subfinder"

    def build_command(self, domain: str) -> list[str]:
        return [self.binary, "-d", domain, "-silent", "-all"]


@register_recon
class AmassAdapter(ExternalReconAdapter):
    name = "amass"
    binary = "amass"
    default_timeout = 600.0

    def build_command(self, domain: str) -> list[str]:
        return [self.binary, "enum", "-passive", "-d", domain, "-silent"]


__all__ = ["ExternalReconAdapter", "SubfinderAdapter", "AmassAdapter", "parse_subdomain_lines"]
