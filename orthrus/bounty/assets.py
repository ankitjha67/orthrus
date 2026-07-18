"""Expand a wildcard scope into the live in-scope hosts to actually scan.

A program scope like ``*.example.com`` authorizes every subdomain, but you have
to *find* them. This module reuses ORTHRUS's subdomain enumeration (Certificate
Transparency via crt.sh + a DNS brute list, with catch-all wildcard suppression)
to discover live subdomains, then keeps only those that are in scope, not
excluded, and not on the high-sensitivity kill-list — turning ``*.example.com``
into a concrete seed list for the campaign.

crt.sh and DNS are OSINT lookups (not requests to the target), so they run
through a plain client, exactly as the recon engine does.
"""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable

import httpx

from orthrus.bounty import killlist
from orthrus.recon.subdomain_enum import (
    CRTSH,
    MAX_BRUTE,
    SUB_WORDLIST,
    _resolve,
    parse_crtsh,
)
from orthrus.utils.logger import get_logger

logger = get_logger("bounty.assets")

Resolver = Callable[[str], Awaitable[list[str]]]


async def _crtsh(domain: str) -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(CRTSH, params={"q": f"%.{domain}", "output": "json"})
            if resp.status_code == 200:
                return sorted(parse_crtsh(resp.json(), domain))
    except (httpx.HTTPError, ValueError) as exc:
        logger.debug("crt.sh query failed for %s: %s", domain, exc)
    return []


async def discover_subdomains(
    domain: str,
    *,
    resolve: Resolver = _resolve,
    crtsh: Callable[[str], Awaitable[list[str]]] = _crtsh,
    brute: bool = True,
    limit: int = 2000,
) -> list[str]:
    """Return live subdomains of ``domain`` (crt.sh + DNS brute, wildcard-suppressed)."""
    candidates = list(await crtsh(domain))
    if brute:
        candidates += [f"{p}.{domain}" for p in SUB_WORDLIST[:MAX_BRUTE]]
    candidates = list(dict.fromkeys(candidates))[:limit]
    wildcard = set(await resolve(f"orthrus-{secrets.token_hex(6)}.{domain}"))  # catch-all IPs
    live: list[str] = []
    for fqdn in candidates:
        ips = await resolve(fqdn)
        if ips and not (wildcard and set(ips) == wildcard):
            live.append(fqdn)
    return live


def in_scope_seeds(hosts: list[str], program) -> list[str]:
    """Pure filter: keep in-scope hosts, drop out-of-scope and high-sensitivity ones.

    Discovered hosts that land on the kill-list (gov/mil/edu/health/sanctioned) are
    *silently skipped* — they are never auto-added; the operator must scope them in
    explicitly and attest authorization. Returns ``https://`` seed URLs, deduped.
    """
    out: list[str] = []
    seen: set[str] = set()
    for host in hosts:
        h = (host or "").lower().rstrip(".")
        if not h or h in seen:
            continue
        seen.add(h)
        if not program.is_in_scope(h):
            continue
        if killlist.classify(h) is not None:
            logger.info("bounty: skipping discovered high-sensitivity host %s (attest to include)", h)
            continue
        out.append(f"https://{h}")
    return out


async def expand_program(
    program,
    *,
    discover: Callable[[str], Awaitable[list[str]]] = discover_subdomains,
) -> list[str]:
    """Discover live in-scope subdomains for every in-scope domain → new seed URLs."""
    found: list[str] = []
    for domain in program.domains:
        try:
            found.extend(await discover(domain))
        except Exception:  # a flaky OSINT source must not sink the campaign
            logger.exception("bounty: subdomain discovery failed for %s", domain)
    return in_scope_seeds(found, program)


__all__ = ["discover_subdomains", "in_scope_seeds", "expand_program"]
