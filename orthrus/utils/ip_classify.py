"""Classify an IP address as public or a specific non-public category.

A public DNS record that resolves to an *internal* address (RFC1918, loopback,
link-local, carrier-grade NAT, an IPv6 unique-local prefix, or a cloud metadata
IP) leaks internal network topology and is a strong SSRF-pivot / dangling-internal
-record signal - exactly what ``FindInternalIPSubdomains.sh`` hunts for by hand.
This is the reusable classifier behind the ``internal-exposure`` scanner.

Categories are matched by explicit CIDR membership (not the version-dependent
``ipaddress.is_private`` flag) so the result is stable across Python versions, and
metadata is checked before link-local because 169.254.169.254 lives inside
169.254.0.0/16.
"""

from __future__ import annotations

import ipaddress

_IpNet = ipaddress.IPv4Network | ipaddress.IPv6Network


def _nets(*cidrs: str) -> list[_IpNet]:
    return [ipaddress.ip_network(c) for c in cidrs]


# Ordered: the first matching category wins. Metadata before link-local on purpose.
_CATEGORIES: list[tuple[str, list[_IpNet]]] = [
    ("cloud-metadata", _nets("169.254.169.254/32", "fd00:ec2::254/128", "100.100.100.200/32")),
    ("loopback", _nets("127.0.0.0/8", "::1/128")),
    ("link-local", _nets("169.254.0.0/16", "fe80::/10")),
    ("cgnat", _nets("100.64.0.0/10")),
    ("unique-local", _nets("fc00::/7")),
    ("private", _nets("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")),
    ("reserved", _nets("0.0.0.0/8", "192.0.2.0/24", "198.18.0.0/15", "240.0.0.0/4")),
]

# The categories worth calling out as sensitive infrastructure exposure.
INTERNAL = frozenset({"cloud-metadata", "loopback", "link-local", "cgnat", "unique-local", "private"})


def classify_ip(ip: str) -> str | None:
    """Return the non-public category for ``ip`` (or ``None`` if it is public/global).

    One of: ``cloud-metadata``, ``loopback``, ``link-local``, ``cgnat``,
    ``unique-local``, ``private``, ``reserved``. ``None`` for a normal routable
    address or an unparseable string.
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
    except (ValueError, AttributeError):
        return None
    for category, networks in _CATEGORIES:
        if any(addr.version == net.version and addr in net for net in networks):
            return category
    return None


def is_internal(ip: str) -> bool:
    """True if ``ip`` is an internal/sensitive address worth flagging."""
    return classify_ip(ip) in INTERNAL


__all__ = ["classify_ip", "is_internal", "INTERNAL"]
