"""Subdomain enumeration (PRD §5.1).

DNS brute-force (dnspython async) + Certificate Transparency (crt.sh), with
wildcard-DNS detection to suppress catch-all false positives. Only subdomains
that fall within the authorized scope are yielded as assets.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from orthrus.core import schemas
from orthrus.core.context import ScanContext
from orthrus.recon.base import BaseRecon
from orthrus.recon.permutation import permutations, sub_labels
from orthrus.utils.logger import get_logger

logger = get_logger("recon.subdomain")

CRTSH = "https://crt.sh/"
MAX_BRUTE = 60
MAX_PERMUTATIONS = 150  # altdns-style mutations of CT-discovered labels

SUB_WORDLIST = [
    "www", "api", "dev", "staging", "stage", "test", "admin", "mail", "blog",
    "app", "apps", "portal", "vpn", "m", "mobile", "shop", "store", "secure",
    "gateway", "internal", "beta", "demo", "cdn", "static", "assets", "git",
    "gitlab", "jenkins", "ci", "docs", "support", "help", "dashboard", "auth",
    "login", "sso", "ftp", "smtp", "ns1", "ns2", "db", "database", "redis",
    "grafana", "kibana", "prometheus", "status", "monitor", "old", "new",
]


def parse_crtsh(entries: list[dict], domain: str) -> set[str]:
    """Extract unique in-domain subdomains from a crt.sh JSON response."""
    domain = domain.lower().rstrip(".")
    found: set[str] = set()
    for entry in entries:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lstrip("*.").lower().rstrip(".")
            if name and (name == domain or name.endswith("." + domain)):
                found.add(name)
    return found


def _host_of(target: str) -> str:
    parts = urlsplit(target if "://" in target else f"//{target}")
    return (parts.hostname or target).lower()


async def _resolve(name: str) -> list[str]:
    try:
        import dns.asyncresolver

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0
        answer = await resolver.resolve(name, "A")
        return sorted({r.address for r in answer})
    except Exception:
        return []


class SubdomainEnum(BaseRecon):
    name = "subdomain-enum"

    def applicable(self, ctx: ScanContext) -> bool:
        host = _host_of(ctx.config.target)
        try:
            import ipaddress

            ipaddress.ip_address(host)
            return False  # IP target -> no subdomains
        except ValueError:
            return host.count(".") >= 1

    async def discover(self, ctx: ScanContext) -> AsyncIterator[schemas.Asset]:
        domain = _host_of(ctx.config.target)
        wildcard_ips = await self._wildcard_ips(domain)
        candidates = await self._candidates(ctx, domain)

        seen: set[str] = set()
        for fqdn in candidates:
            if fqdn in seen:
                continue
            seen.add(fqdn)
            if not ctx.scope.host_in_scope(fqdn):
                continue
            ips = await _resolve(fqdn)
            if not ips:
                continue
            if wildcard_ips and set(ips) == wildcard_ips:
                continue  # catch-all wildcard, not a real host
            yield schemas.Asset(fqdn=fqdn, ips=ips, discovery_method="subdomain-enum")

    async def _wildcard_ips(self, domain: str) -> set[str]:
        probe = f"orthrus-{secrets.token_hex(6)}.{domain}"
        return set(await _resolve(probe))

    async def _candidates(self, ctx: ScanContext, domain: str) -> list[str]:
        brute = [f"{p}.{domain}" for p in SUB_WORDLIST[:MAX_BRUTE]]
        ct = await self._crtsh(domain)
        # Widen the surface: mutate the labels CT actually revealed (api -> api-dev,
        # staging-api, api2, ...) and let the resolver keep the ones that answer.
        perms = permutations(sub_labels(ct, domain), domain, cap=MAX_PERMUTATIONS)
        return list(dict.fromkeys([*ct, *brute, *perms]))

    async def _crtsh(self, domain: str) -> list[str]:
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(CRTSH, params={"q": f"%.{domain}", "output": "json"})
                if resp.status_code == 200:
                    return sorted(parse_crtsh(resp.json(), domain))
        except (httpx.HTTPError, ValueError) as exc:
            logger.debug("crt.sh query failed for %s: %s", domain, exc)
        return []


__all__ = ["SubdomainEnum", "parse_crtsh", "SUB_WORDLIST"]
