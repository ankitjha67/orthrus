"""Target scope validation engine.

This is HYDRA's primary safety control. Every outgoing request is checked here
before it leaves the process (see ``hydra.core.http_client``). The policy is
**deny by default**: a host/port/path is only permitted if the engagement's
``ScopeConfig`` explicitly authorizes it.

Do not weaken this module to "make a scan work". An out-of-scope request is a
potential legal and ethical violation, not a bug to route around.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from hydra.core.config import ScopeConfig

_DEFAULT_SCHEME_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}


class ScopeViolation(Exception):
    """Raised when a request target falls outside the authorized scope."""

    def __init__(self, url: str, reason: str) -> None:
        self.url = url
        self.reason = reason
        super().__init__(f"Out of scope: {url} ({reason})")


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    third_party: bool = False


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _host_matches_domain(host: str, pattern: str) -> bool:
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[2:]
        # Wildcard authorizes the apex and any subdomain (common engagement convention).
        return host == suffix or host.endswith("." + suffix)
    return host == pattern


def _ip_in_ranges(host: str, ranges: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    for rng in ranges:
        try:
            if ip in ipaddress.ip_network(rng, strict=False):
                return True
        except ValueError:
            continue
    return False


class ScopeValidator:
    def __init__(self, scope: ScopeConfig) -> None:
        self.scope = scope
        self._exclude_res: list[re.Pattern[str]] = []
        for pat in scope.exclude_paths:
            try:
                self._exclude_res.append(re.compile(pat))
            except re.error:
                # A malformed exclusion must fail safe: treat as literal substring match.
                self._exclude_res.append(re.compile(re.escape(pat)))

    @staticmethod
    def _port_for(scheme: str, explicit: int | None) -> int | None:
        if explicit is not None:
            return explicit
        return _DEFAULT_SCHEME_PORTS.get(scheme.lower())

    def host_in_scope(self, host: str) -> bool:
        if not host:
            return False
        if _is_ip_literal(host):
            return _ip_in_ranges(host, self.scope.ip_ranges)
        return any(_host_matches_domain(host, d) for d in self.scope.domains)

    def ip_in_scope(self, ip: str) -> bool:
        """Used for DNS-rebinding protection: validate the *resolved* IP too."""
        return _ip_in_ranges(ip, self.scope.ip_ranges) if self.scope.ip_ranges else True

    def check(self, url: str) -> ScopeDecision:
        parts = urlsplit(url)
        host = parts.hostname
        if not host:
            return ScopeDecision(False, "no host in URL")

        path = parts.path or "/"
        for rx in self._exclude_res:
            if rx.search(path):
                return ScopeDecision(False, f"path excluded by rule '{rx.pattern}'")

        in_scope = self.host_in_scope(host)
        if not in_scope:
            if self.scope.block_third_party:
                return ScopeDecision(False, "host not in authorized scope")
            return ScopeDecision(True, "third-party host (allowed, flagged)", third_party=True)

        if self.scope.ports:
            try:
                port = self._port_for(parts.scheme, parts.port)
            except ValueError:
                return ScopeDecision(False, "invalid port in URL")
            if port is not None and port not in self.scope.ports:
                return ScopeDecision(False, f"port {port} not in authorized port list")

        return ScopeDecision(True, "in scope")

    def is_allowed(self, url: str) -> bool:
        return self.check(url).allowed

    def assert_in_scope(self, url: str) -> None:
        decision = self.check(url)
        if not decision.allowed:
            raise ScopeViolation(url, decision.reason)

    def validate_redirect(self, to_url: str) -> ScopeDecision:
        """A redirect hop is followed only if it stays within scope (PRD §12.3)."""
        return self.check(to_url)

    def filter_in_scope(self, urls: list[str]) -> list[str]:
        return [u for u in urls if self.is_allowed(u)]


__all__ = ["ScopeValidator", "ScopeDecision", "ScopeViolation"]
