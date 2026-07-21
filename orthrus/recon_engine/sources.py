"""Pure-Python recon sources (PRD §7.2) - no external binary required.

These adapters query trusted third-party data sources (CT logs, passive DNS,
web archives) or resolve DNS directly, so they work out of the box. They fetch
from data providers (crt.sh / certspotter / web.archive.org), never from the
target, mirroring the existing recon modules and intel feeds. Network calls go
through ``_get_json`` / ``_get_text`` / ``_resolve`` so tests can inject fixtures.
"""

from __future__ import annotations

import httpx

from orthrus.recon.subdomain_enum import SUB_WORDLIST, parse_crtsh
from orthrus.recon.subdomain_enum import _resolve as _dns_resolve
from orthrus.recon_engine.base import DiscoveredAsset, ReconAdapter, ReconScope, register_recon
from orthrus.utils.logger import get_logger

logger = get_logger("recon_engine.sources")

_UA = {"User-Agent": "orthrus-recon/2.0"}


async def _get_json(url: str, timeout_s: float = 25.0):
    async with httpx.AsyncClient(timeout=timeout_s, follow_redirects=True) as client:
        resp = await client.get(url, headers=_UA)
        resp.raise_for_status()
        return resp.json()


async def _get_text(url: str, timeout_s: float = 25.0) -> str:
    async with httpx.AsyncClient(timeout=timeout_s, follow_redirects=True) as client:
        resp = await client.get(url, headers=_UA)
        resp.raise_for_status()
        return resp.text


async def _resolve(name: str) -> list[str]:
    return await _dns_resolve(name)


def _in_domain(name: str, domain: str) -> bool:
    name = name.lstrip("*.").lower().rstrip(".")
    return bool(name) and (name == domain or name.endswith("." + domain))


@register_recon
class CrtShAdapter(ReconAdapter):
    """Certificate-transparency subdomains via crt.sh."""

    name = "crtsh"

    async def discover(self, scope: ReconScope) -> list[DiscoveredAsset]:
        found: list[DiscoveredAsset] = []
        for domain in scope.domains:
            try:
                entries = await _get_json(f"https://crt.sh/?q=%25.{domain}&output=json")
            except (httpx.HTTPError, ValueError) as exc:
                logger.info("crtsh: %s failed (%s)", domain, exc)
                continue
            for sub in parse_crtsh(entries if isinstance(entries, list) else [], domain):
                found.append(DiscoveredAsset("subdomain", sub, self.name))
        return found


@register_recon
class CertspotterAdapter(ReconAdapter):
    """Certificate-transparency subdomains via the certspotter API."""

    name = "certspotter"

    async def discover(self, scope: ReconScope) -> list[DiscoveredAsset]:
        found: list[DiscoveredAsset] = []
        for domain in scope.domains:
            url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
                   "&include_subdomains=true&expand=dns_names")
            try:
                data = await _get_json(url)
            except (httpx.HTTPError, ValueError) as exc:
                logger.info("certspotter: %s failed (%s)", domain, exc)
                continue
            for issuance in data if isinstance(data, list) else []:
                for name in issuance.get("dns_names", []) or []:
                    if _in_domain(name, domain):
                        found.append(DiscoveredAsset(
                            "subdomain", name.lstrip("*.").lower().rstrip("."), self.name))
        return found


@register_recon
class DnsBruteAdapter(ReconAdapter):
    """Active DNS bruteforce over a small high-signal wordlist."""

    name = "dns-brute"

    async def discover(self, scope: ReconScope) -> list[DiscoveredAsset]:
        found: list[DiscoveredAsset] = []
        for domain in scope.domains:
            for label in SUB_WORDLIST:
                host = f"{label}.{domain}"
                ips = await _resolve(host)
                if ips:
                    found.append(DiscoveredAsset("subdomain", host, self.name, {"ips": ips}))
        return found


@register_recon
class WaybackAdapter(ReconAdapter):
    """Historical URLs from the Wayback Machine CDX index."""

    name = "wayback"

    async def discover(self, scope: ReconScope) -> list[DiscoveredAsset]:
        found: list[DiscoveredAsset] = []
        for domain in scope.domains:
            url = (f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
                   "&output=text&fl=original&collapse=urlkey&limit=10000")
            try:
                text = await _get_text(url)
            except httpx.HTTPError as exc:
                logger.info("wayback: %s failed (%s)", domain, exc)
                continue
            for line in text.splitlines():
                loc = line.strip()
                if loc:
                    found.append(DiscoveredAsset("url", loc, self.name, {"historical": True}))
        return found


__all__ = ["CrtShAdapter", "CertspotterAdapter", "DnsBruteAdapter", "WaybackAdapter"]
