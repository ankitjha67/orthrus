"""Detect whether an IP belongs to a known CDN / edge provider.

Used to surface origin-IP exposure: when an app is fronted by a CDN (Cloudflare,
Fastly, CloudFront) but an in-scope host resolves to a *non-CDN* address, that address
is a candidate origin that bypasses the edge's WAF / rate-limit / geo controls - the
single leak that retroactively solves a Cloudflare-blocked engagement.

Ranges are the providers' published anycast blocks. Cloudflare is complete (the common
case); Fastly and CloudFront carry a representative subset. Matching by explicit CIDR,
so the result is stable and dependency-free.
"""

from __future__ import annotations

import ipaddress

_IpNet = ipaddress.IPv4Network | ipaddress.IPv6Network


def _nets(*cidrs: str) -> list[_IpNet]:
    return [ipaddress.ip_network(c) for c in cidrs]


_CDN: dict[str, list[_IpNet]] = {
    "Cloudflare": _nets(
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
        "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    ),
    "Fastly": _nets(
        "151.101.0.0/16", "199.232.0.0/16", "23.235.32.0/20", "43.249.72.0/22",
        "103.244.50.0/24", "146.75.0.0/16", "2a04:4e40::/32",
    ),
    "CloudFront": _nets(
        "13.32.0.0/15", "13.224.0.0/14", "52.84.0.0/15", "54.182.0.0/16",
        "54.192.0.0/16", "99.84.0.0/16", "205.251.192.0/19", "130.176.0.0/16",
    ),
}


def cdn_of(ip: str) -> str | None:
    """Return the CDN provider name for ``ip``, or ``None`` if not a known edge IP."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except (ValueError, AttributeError):
        return None
    for name, networks in _CDN.items():
        if any(addr.version == net.version and addr in net for net in networks):
            return name
    return None


def is_cdn(ip: str) -> bool:
    return cdn_of(ip) is not None


__all__ = ["cdn_of", "is_cdn"]
