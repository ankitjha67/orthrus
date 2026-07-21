"""Host gathering - consolidate the host footprint from many passive sources.

Given a target, this module casts a wide *passive* net to gather every related
host it can, then folds them into one deduplicated inventory:

* **Certificate Transparency** (crt.sh) - subdomains seen in issued certs.
* **Reverse-IP / co-hosting** - other hostnames sharing the target's IP(s).
* **Reverse-DNS netblock sweep** - PTR records across the target IP's /24,
  surfacing neighbouring hosts on the same network.
* **Wayback Machine** - hostnames seen in historically archived URLs.

Everything queries public databases / third-party OSINT services *about* the
target - no host-discovery packet is sent to the gathered hosts themselves.

Scope discipline: only hosts that fall **within the authorised scope** are
emitted as scannable :class:`Asset`s. Co-hosted hosts that land outside scope
are still *gathered and counted* (situational awareness - e.g. shared-hosting
exposure) but are flagged ``in_scope=False`` and never fed to the scan phase.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

from orthrus.core import schemas
from orthrus.core.context import ScanContext
from orthrus.recon.base import BaseRecon
from orthrus.recon.ip_intel import _resolve_ips, _reverse_ptr
from orthrus.recon.subdomain_enum import parse_crtsh
from orthrus.recon.wayback import parse_wayback
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeValidator

logger = get_logger("recon.host-gather")

CRTSH = "https://crt.sh/"
WAYBACK_CDX = "http://web.archive.org/cdx/search/cdx"
REVERSE_IP_API = "https://api.hackertarget.com/reverseiplookup/"

NETBLOCK_CAP = 256  # /24 sweep ceiling
NETBLOCK_CONCURRENCY = 40
MAX_HOSTS = 5000  # bound total gathered candidates
MAX_RESOLVE = 250  # cap forward-resolutions of in-scope hosts

# Lines the reverse-IP API returns instead of data when it has nothing / is
# rate-limited; never treat these as hostnames.
_API_NOISE = ("error", "api count exceeded", "no records", "no dns")

# A conservative hostname matcher: at least one label + an alphabetic TLD, so
# IP literals and junk lines are rejected.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,62})\.)+[a-z][a-z0-9-]{1,62}$"
)


@dataclass
class GatheredHost:
    """One host in the consolidated inventory."""

    fqdn: str
    ips: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    in_scope: bool = False


def valid_hostname(name: str) -> bool:
    return bool(_HOSTNAME_RE.match(name))


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _host_of(target: str) -> str:
    return (urlsplit(target if "://" in target else f"//{target}").hostname or target).lower()


def parse_reverse_ip(text: str) -> list[str]:
    """Parse the reverse-IP API's plaintext body into a clean hostname list."""
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip().lower().rstrip(".")
        if not line or any(noise in line for noise in _API_NOISE):
            continue
        if valid_hostname(line):
            out.append(line)
    return list(dict.fromkeys(out))


def hosts_from_urls(urls: list[str]) -> list[str]:
    """Extract unique hostnames from a list of URLs."""
    out: list[str] = []
    for url in urls:
        host = urlsplit(url if "://" in url else f"//{url}").hostname
        if host:
            out.append(host.lower().rstrip("."))
    return list(dict.fromkeys(out))


def net24_addresses(ip: str, cap: int = NETBLOCK_CAP) -> list[str]:
    """Return the addresses of the /24 containing an IPv4 address (capped)."""
    if _is_ip(ip) and ipaddress.ip_address(ip).version == 4:
        base = ip.rsplit(".", 1)[0]
        return [f"{base}.{i}" for i in range(256)][:cap]
    return []


# ------------------------------------------------------------------ sources
async def _crtsh_hosts(domain: str) -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=25.0) as client:
            resp = await client.get(CRTSH, params={"q": f"%.{domain}", "output": "json"})
            if resp.status_code == 200:
                return sorted(parse_crtsh(resp.json(), domain))
    except (httpx.HTTPError, ValueError) as exc:
        logger.debug("crt.sh query failed for %s: %s", domain, exc)
    return []


async def _wayback_hosts(domain: str) -> list[str]:
    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": 1000,
    }
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(WAYBACK_CDX, params=params)
            rows = resp.json() if resp.status_code == 200 else []
        return hosts_from_urls(parse_wayback(rows))
    except (httpx.HTTPError, ValueError) as exc:
        logger.debug("wayback query failed for %s: %s", domain, exc)
    return []


async def _reverse_ip_hosts(ip: str) -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(REVERSE_IP_API, params={"q": ip})
            if resp.status_code == 200:
                return parse_reverse_ip(resp.text)
    except httpx.HTTPError as exc:
        logger.debug("reverse-ip lookup failed for %s: %s", ip, exc)
    return []


async def _netblock_ptr_sweep(ip: str, cap: int = NETBLOCK_CAP) -> list[str]:
    addrs = net24_addresses(ip, cap)
    if not addrs:
        return []
    try:
        import dns.asyncresolver
    except Exception:
        return []
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = resolver.lifetime = 3.0
    sem = asyncio.Semaphore(NETBLOCK_CONCURRENCY)
    names: set[str] = set()

    async def _one(addr: str) -> None:
        async with sem:
            for name in await _reverse_ptr(resolver, addr):
                low = name.lower().rstrip(".")
                if valid_hostname(low):
                    names.add(low)

    await asyncio.gather(*(_one(a) for a in addrs), return_exceptions=True)
    return sorted(names)


# --------------------------------------------------------------- aggregation
async def gather_hosts(
    host: str,
    scope: ScopeValidator,
    *,
    reverse_ip: bool = True,
    netblock: bool = True,
    ct_logs: bool = True,
    wayback: bool = True,
    netblock_cap: int = NETBLOCK_CAP,
    max_hosts: int = MAX_HOSTS,
) -> list[GatheredHost]:
    """Gather every host related to ``host`` from the enabled passive sources.

    Returns a deduplicated, scope-flagged inventory sorted in-scope-first.
    """
    host = host.lower().rstrip(".")
    is_ip = _is_ip(host)
    candidates: dict[str, set[str]] = {}
    known_ips: dict[str, set[str]] = {}

    def add(name: str, source: str, ip: str | None = None) -> None:
        name = name.strip().lower().rstrip(".")
        if not name or not valid_hostname(name):
            return
        if name not in candidates and len(candidates) >= max_hosts:
            return
        candidates.setdefault(name, set()).add(source)
        if ip:
            known_ips.setdefault(name, set()).add(ip)

    if not is_ip:
        add(host, "target")
    seed_ips = await _resolve_ips(host)

    if ct_logs and not is_ip:
        for name in await _crtsh_hosts(host):
            add(name, "crt.sh")
    if wayback and not is_ip:
        for name in await _wayback_hosts(host):
            add(name, "wayback")
    if reverse_ip:
        for ip in seed_ips[:4]:
            for name in await _reverse_ip_hosts(ip):
                add(name, "reverse-ip", ip)
    if netblock:
        for ip in seed_ips[:2]:
            for name in await _netblock_ptr_sweep(ip, netblock_cap):
                add(name, "reverse-dns")

    results: list[GatheredHost] = []
    resolved = 0
    for fqdn in sorted(candidates):
        in_scope = scope.host_in_scope(fqdn)
        ips = sorted(known_ips.get(fqdn, set()))
        if in_scope and not ips and resolved < MAX_RESOLVE:
            ips = await _resolve_ips(fqdn)
            resolved += 1
        results.append(GatheredHost(fqdn, ips, sorted(candidates[fqdn]), in_scope))
    results.sort(key=lambda g: (not g.in_scope, g.fqdn))
    return results


class HostGathering(BaseRecon):
    """Recon module: feed in-scope gathered hosts into the scan pipeline."""

    name = "host-gather"

    def applicable(self, ctx: ScanContext) -> bool:
        return bool(_host_of(ctx.config.target))

    async def discover(self, ctx: ScanContext) -> AsyncIterator[schemas.Asset]:
        host = _host_of(ctx.config.target)
        if not ctx.scope.host_in_scope(host):
            logger.debug("host-gather: target %s not in authorized scope; skipping", host)
            return
        gathered = await gather_hosts(host, ctx.scope)
        in_scope = [g for g in gathered if g.in_scope]
        out_scope = len(gathered) - len(in_scope)
        logger.info(
            "host-gather: %d in-scope host(s); %d co-hosted/out-of-scope gathered (not scanned)",
            len(in_scope), out_scope,
        )
        for g in in_scope:
            method = ("host-gather:" + ",".join(g.sources))[:64]
            yield schemas.Asset(fqdn=g.fqdn, ips=g.ips, discovery_method=method)


__all__ = [
    "HostGathering",
    "GatheredHost",
    "gather_hosts",
    "parse_reverse_ip",
    "hosts_from_urls",
    "net24_addresses",
    "valid_hostname",
]
