"""IP-address intelligence recon - infrastructure OSINT (PRD §5.1).

Given an in-scope target host or IP, this module enriches it with passive
network intelligence about the *infrastructure* it runs on:

* **Reverse DNS (PTR)** - the hostname(s) the IP points back to.
* **ASN / network owner** - the autonomous system announcing the IP, its
  organisation name, and the covering BGP prefix, resolved via Team Cymru's
  IP-to-ASN service over DNS (no API key required).
* **Allocation country / registry** - the RIR allocation country code and
  registry. This is a coarse, allocation-level locator - *not* a precise
  geolocation, and never a person's location.
* **Cloud / hosting attribution** - a best-effort provider label derived from
  the AS organisation (AWS, Google Cloud, Azure, Cloudflare, ...).

Every lookup is **passive**: it queries public DNS databases *about* the IP and
sends no packet to the target itself. The module only enriches addresses that
the authorised target resolves to and that fall within any declared IP ranges,
so the engagement boundary holds. This recons infrastructure for an authorised
assessment - it is not a tool for locating or tracking individual people.
"""

from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from orthrus.core import schemas
from orthrus.core.context import ScanContext
from orthrus.recon.base import BaseRecon
from orthrus.utils.logger import get_logger

logger = get_logger("recon.ip-intel")

MAX_IPS = 8  # cap enrichment work per engagement

# AS-organisation substring -> friendly cloud/hosting label. Order matters only
# for readability; matches are by substring on the upper-cased org string.
_CLOUD_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("AMAZON", "AWS"),
    ("AWS", "AWS"),
    ("GOOGLE", "Google Cloud"),
    ("MICROSOFT", "Azure"),
    ("AZURE", "Azure"),
    ("CLOUDFLARE", "Cloudflare"),
    ("DIGITALOCEAN", "DigitalOcean"),
    ("AKAMAI", "Akamai"),
    ("FASTLY", "Fastly"),
    ("OVH", "OVH"),
    ("HETZNER", "Hetzner"),
    ("LINODE", "Linode"),
    ("ORACLE", "Oracle Cloud"),
    ("ALIBABA", "Alibaba Cloud"),
    ("TENCENT", "Tencent Cloud"),
    ("VULTR", "Vultr"),
    ("CONTABO", "Contabo"),
)


def attribute_cloud(as_org: str | None) -> str | None:
    """Best-effort hosting/cloud provider label from an AS-organisation string."""
    if not as_org:
        return None
    upper = as_org.upper()
    for needle, label in _CLOUD_SIGNATURES:
        if needle in upper:
            return label
    return None


def parse_cymru_origin(txt: str) -> dict[str, str]:
    """Parse a Team Cymru *origin* TXT record into its fields.

    Format: ``ASN | BGP-prefix | CC | registry | allocated``
    e.g. ``"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"``. For a multi-origin
    prefix the ASN field may hold several space-separated numbers; we take the
    first.
    """
    parts = [p.strip() for p in txt.strip().strip('"').split("|")]
    if len(parts) < 5:
        return {}
    asn = parts[0].split()[0] if parts[0].strip() else ""
    return {
        "asn": asn,
        "network": parts[1],
        "country": parts[2],
        "registry": parts[3],
        "allocated": parts[4],
    }


def parse_cymru_asname(txt: str) -> str | None:
    """Parse a Team Cymru *AS-name* TXT record into the organisation name.

    Format: ``ASN | CC | registry | allocated | AS-NAME``
    e.g. ``"15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"``.
    """
    parts = [p.strip() for p in txt.strip().strip('"').split("|")]
    return parts[4] if len(parts) >= 5 and parts[4] else None


def _origin_query(ip: str) -> str:
    """Build the Team Cymru origin query name for an IPv4/IPv6 address."""
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    # IPv6: nibble-reverse, swap the ip6.arpa suffix for origin6.asn.cymru.com.
    import dns.reversename

    rev = dns.reversename.from_address(ip).to_text()  # '<nibbles>.ip6.arpa.'
    nibbles = rev[: -len("ip6.arpa.")]  # keeps the trailing dot
    return nibbles + "origin6.asn.cymru.com"


def _host_of(target: str) -> str:
    return (urlsplit(target if "://" in target else f"//{target}").hostname or target).lower()


async def _resolve_ips(host: str) -> list[str]:
    """Forward-resolve a host to its A/AAAA addresses (or ``[host]`` if an IP)."""
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        import dns.asyncresolver

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = resolver.lifetime = 4.0
        ips: list[str] = []
        for rtype in ("A", "AAAA"):
            try:
                ans = await resolver.resolve(host, rtype)
                ips.extend(sorted(r.address for r in ans))
            except Exception:
                continue
        return list(dict.fromkeys(ips))
    except Exception:
        return []


async def _reverse_ptr(resolver, ip: str) -> list[str]:  # type: ignore[no-untyped-def]
    try:
        import dns.reversename

        ans = await resolver.resolve(dns.reversename.from_address(ip), "PTR")
        return sorted(str(r).rstrip(".") for r in ans)
    except Exception:
        return []


async def _cymru_lookup(resolver, ip: str) -> dict[str, str]:  # type: ignore[no-untyped-def]
    """Team Cymru IP-to-ASN over DNS: origin record, then the AS-name record."""
    try:
        ans = await resolver.resolve(_origin_query(ip), "TXT")
    except Exception:
        return {}
    info = parse_cymru_origin(str(ans[0]))
    asn_num = info.get("asn")
    if not asn_num:
        return info
    try:
        ans = await resolver.resolve(f"AS{asn_num}.asn.cymru.com", "TXT")
        org = parse_cymru_asname(str(ans[0]))
        if org:
            info["as_org"] = org
    except Exception:
        pass
    info["asn"] = f"AS{asn_num}"  # normalise to the AS-prefixed form
    return info


class IpIntelRecon(BaseRecon):
    """Enrich the target's resolved IP(s) with passive infrastructure intel."""

    name = "ip-intel"

    def applicable(self, ctx: ScanContext) -> bool:
        return bool(_host_of(ctx.config.target))

    async def discover(self, ctx: ScanContext) -> AsyncIterator[schemas.Asset]:
        try:
            import dns.asyncresolver
        except Exception:
            logger.debug("dnspython unavailable; skipping IP intelligence")
            return

        host = _host_of(ctx.config.target)
        # Authorisation gate: only enrich a target that is in declared scope.
        if not ctx.scope.host_in_scope(host):
            logger.debug("ip-intel: target %s not in authorized scope; skipping", host)
            return

        ips = await _resolve_ips(host)
        if not ips:
            logger.info("ip-intel: %s did not resolve to any IP address", host)
            return

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = resolver.lifetime = 4.0

        enriched_ips: list[str] = []
        primary: schemas.IpIntel | None = None
        for ip in ips[:MAX_IPS]:
            # Honour any declared IP ranges (permissive for domain-only scopes).
            if not ctx.scope.ip_in_scope(ip):
                logger.debug("ip-intel: %s outside declared IP ranges; skipping", ip)
                continue
            intel = await self._enrich(resolver, ip)
            self._log_intel(host, intel)
            enriched_ips.append(ip)
            if primary is None:
                primary = intel

        if not enriched_ips:
            return
        yield schemas.Asset(
            fqdn=host,
            ips=enriched_ips,
            discovery_method="ip-intel",
            ip_intel=primary,
        )

    async def _enrich(self, resolver, ip: str) -> schemas.IpIntel:  # type: ignore[no-untyped-def]
        ptr = await _reverse_ptr(resolver, ip)
        cymru = await _cymru_lookup(resolver, ip)
        as_org = cymru.get("as_org")
        return schemas.IpIntel(
            ip=ip,
            ptr=ptr,
            asn=cymru.get("asn"),
            as_org=as_org,
            network=cymru.get("network"),
            country=cymru.get("country"),
            registry=cymru.get("registry"),
            allocated=cymru.get("allocated"),
            cloud_provider=attribute_cloud(as_org),
        )

    @staticmethod
    def _log_intel(host: str, intel: schemas.IpIntel) -> None:
        bits = [f"ip={intel.ip}"]
        if intel.ptr:
            bits.append(f"ptr={','.join(intel.ptr)}")
        if intel.asn:
            bits.append(f"{intel.asn} ({intel.as_org or '?'})")
        if intel.network:
            bits.append(f"net={intel.network}")
        if intel.country:
            bits.append(f"cc={intel.country}/{intel.registry or '?'}")
        if intel.cloud_provider:
            bits.append(f"cloud={intel.cloud_provider}")
        logger.info("ip-intel %s -> %s", host, " | ".join(bits))


__all__ = [
    "IpIntelRecon",
    "attribute_cloud",
    "parse_cymru_origin",
    "parse_cymru_asname",
]
