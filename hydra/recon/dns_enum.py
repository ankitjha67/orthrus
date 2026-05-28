"""DNS record enumeration + zone transfer (PRD §5.1.1 / dns_enum).

Enumerates A/AAAA/CNAME/MX/NS/TXT records for the target domain and attempts an
AXFR zone transfer against each nameserver (a misconfiguration that leaks the
whole zone). Domain targets only; uses dnspython.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from hydra.core import schemas
from hydra.core.context import ScanContext
from hydra.recon.base import BaseRecon
from hydra.utils.logger import get_logger

logger = get_logger("recon.dns")

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")


def _host_of(target: str) -> str:
    return (urlsplit(target if "://" in target else f"//{target}").hostname or target).lower()


class DnsEnum(BaseRecon):
    name = "dns-enum"

    def applicable(self, ctx: ScanContext) -> bool:
        host = _host_of(ctx.config.target)
        try:
            import ipaddress

            ipaddress.ip_address(host)
            return False
        except ValueError:
            return host.count(".") >= 1

    async def discover(self, ctx: ScanContext) -> AsyncIterator[schemas.Asset]:
        try:
            import dns.asyncresolver
            import dns.query
            import dns.zone
        except Exception:
            logger.debug("dnspython unavailable; skipping DNS enum")
            return

        domain = _host_of(ctx.config.target)
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = resolver.lifetime = 4.0

        records: dict[str, list[str]] = {}
        for rtype in RECORD_TYPES:
            try:
                answer = await resolver.resolve(domain, rtype)
                records[rtype] = sorted(str(r) for r in answer)
            except Exception:
                continue
        if records:
            logger.info("DNS records for %s: %s", domain, {k: len(v) for k, v in records.items()})

        ips = records.get("A", []) + records.get("AAAA", [])
        cname = records.get("CNAME", [])
        yield schemas.Asset(
            fqdn=domain, ips=ips, cname_chain=cname, discovery_method="dns-enum"
        )

        # Zone transfer (AXFR) against each nameserver.
        for ns in records.get("NS", []):
            for name in await self._try_axfr(resolver, domain, ns.rstrip(".")):
                if name != domain and ctx.scope.host_in_scope(name):
                    yield schemas.Asset(fqdn=name, discovery_method="dns-axfr")

    async def _try_axfr(self, resolver, domain: str, ns: str) -> list[str]:  # type: ignore[no-untyped-def]
        import dns.query
        import dns.zone

        try:
            ns_answer = await resolver.resolve(ns, "A")
            ns_ip = str(ns_answer[0])
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5.0))
            names = [f"{n}.{domain}" if str(n) != "@" else domain for n in zone.nodes]
            logger.warning("AXFR zone transfer succeeded against %s (%d names)", ns, len(names))
            return names
        except Exception:
            return []


__all__ = ["DnsEnum"]
