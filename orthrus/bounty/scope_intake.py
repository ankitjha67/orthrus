"""Parse a bug-bounty program's scope into an enforceable engagement boundary.

The scope file is a plain-text list (the lingua franca of program scopes), one
entry per line:

    # comment lines start with '#'
    *.example.com            # wildcard: the apex and any subdomain, in scope
    api.example.com          # a specific host, in scope
    https://app.example.com  # a specific URL to seed the crawl from
    10.0.0.0/24              # a CIDR range, in scope
    !admin.example.com       # a leading '!' marks an OUT-OF-SCOPE exclusion
    !*.internal.example.com  # out-of-scope wildcard

Everything without a ``!`` is in scope; ``!`` lines carve exclusions back out.
The result feeds both the scope-enforced HTTP client (via :class:`ScopeConfig`)
and the campaign's own asset filter, so a discovered subdomain that falls under
an exclusion is never scanned.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from orthrus.core.config import ScopeConfig


def _as_cidr(token: str) -> str | None:
    try:
        return str(ipaddress.ip_network(token, strict=False))
    except ValueError:
        return None


def _host_and_seed(token: str) -> tuple[str, str | None]:
    """Return (host-pattern, seed-URL-or-None) for an in-scope entry."""
    if "://" in token:
        parts = urlsplit(token)
        return (parts.hostname or "").lower(), token
    host = token.lower().rstrip("/")
    if host.startswith("*."):
        return host, None  # a wildcard has no single seed; the apex is added by the caller
    return host, f"https://{host}"


def _base_host(pattern: str) -> str:
    """Strip a leading ``*.`` so ``*.example.com`` and ``example.com`` compare equal."""
    p = pattern.lower().strip()
    return p[2:] if p.startswith("*.") else p


def _host_matches(host: str, pattern: str) -> bool:
    """A host matches a domain pattern if it equals it or is a subdomain of it."""
    host = (host or "").lower().rstrip(".")
    base = _base_host(pattern)
    if not host or not base:
        return False
    if _as_cidr(base):
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(base, strict=False)
        except ValueError:
            return False
    return host == base or host.endswith("." + base)


@dataclass
class ProgramScope:
    """An authorized bug-bounty scope: what to scan, and what to never touch."""

    seeds: list[str] = field(default_factory=list)          # URLs to start scanning from
    domains: list[str] = field(default_factory=list)        # in-scope host / wildcard patterns
    ip_ranges: list[str] = field(default_factory=list)      # in-scope CIDRs
    out_of_scope: list[str] = field(default_factory=list)   # exclusions (host / wildcard / CIDR)

    def scope_config(self) -> ScopeConfig:
        """The deny-by-default :class:`ScopeConfig` for the scope-enforced client."""
        sc = ScopeConfig(domains=list(self.domains), ip_ranges=list(self.ip_ranges))
        sc.block_third_party = True
        return sc

    def is_out_of_scope(self, host: str) -> bool:
        return any(_host_matches(host, pat) for pat in self.out_of_scope)

    def is_in_scope(self, host: str) -> bool:
        """In scope iff it matches an in-scope pattern and no exclusion."""
        if not host or self.is_out_of_scope(host):
            return False
        in_domains = any(_host_matches(host, d) for d in self.domains)
        in_ranges = any(_host_matches(host, c) for c in self.ip_ranges)
        return in_domains or in_ranges

    def in_scope_seeds(self) -> list[str]:
        """Seed URLs whose host is in scope (an exclusion can veto a seed)."""
        out = []
        for seed in self.seeds:
            host = (urlsplit(seed).hostname or "").lower()
            if host and not self.is_out_of_scope(host):
                out.append(seed)
        return out


def parse_program_scope(text: str) -> ProgramScope:
    """Parse a scope file's text into a :class:`ProgramScope` (see module docstring)."""
    ps = ProgramScope()
    seen_seed: set[str] = set()
    seen_domain: set[str] = set()
    seen_oos: set[str] = set()

    def _add_domain(base: str) -> None:
        if base and base not in seen_domain:
            seen_domain.add(base)
            ps.domains.append(base)

    def _add_seed(url: str) -> None:
        if url and url not in seen_seed:
            seen_seed.add(url)
            ps.seeds.append(url)

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        out_of_scope = line.startswith("!")
        if out_of_scope:
            line = line[1:].strip()
            if not line:
                continue

        cidr = _as_cidr(line)
        if cidr:
            if out_of_scope:
                if cidr not in seen_oos:
                    seen_oos.add(cidr)
                    ps.out_of_scope.append(cidr)
            else:
                if cidr not in ps.ip_ranges:
                    ps.ip_ranges.append(cidr)
                # a single host (/32, /128) is worth seeding directly
                net = ipaddress.ip_network(cidr, strict=False)
                if net.num_addresses == 1:
                    _add_seed(f"http://{net.network_address}")
            continue

        host, seed = _host_and_seed(line)
        base = _base_host(host)
        ip_host = _as_cidr(base)  # an IP given as a bare host or inside a URL
        if out_of_scope:
            key = ip_host or base
            if key and key not in seen_oos:
                seen_oos.add(key)
                ps.out_of_scope.append(ip_host or host)  # keep wildcard/CIDR form for matching
            continue
        if ip_host:
            if ip_host not in ps.ip_ranges:  # the scope engine matches IPs via ip_ranges, not domains
                ps.ip_ranges.append(ip_host)
        else:
            _add_domain(base)
        if seed:
            _add_seed(seed)
        elif host.startswith("*."):
            _add_seed(f"https://{base}")  # scan the apex; subdomain enumeration expands from there
    return ps


__all__ = ["ProgramScope", "parse_program_scope"]
