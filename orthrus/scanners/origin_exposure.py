"""Origin-IP exposure behind a CDN.

If an app is fronted by a CDN (Cloudflare/Fastly/CloudFront) but an in-scope host
resolves to a *public non-CDN* address, that address is a candidate **origin** reachable
directly - bypassing the edge's WAF, rate limiting, and geo controls, and often exposing
debug routes or unauthenticated API versions the edge would hide. On a Cloudflare-blocked
engagement, one verified origin retroactively solves the 403 / geo-block / clearance-churn
problem.

Passive and DNS-only: it reasons over the IPs already resolved during recon
(``ctx.assets``), so it is a *lead* (tentative) - confirming the origin serves the app
needs a direct probe, which a domain-only scope may forbid. Internal (RFC1918) addresses
are the ``internal-exposure`` scanner's job and are excluded here.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.cdn import cdn_of
from orthrus.utils.ip_classify import classify_ip

SCANNER_NAME = "origin-exposure"

# Subdomains that legitimately resolve to their own (non-CDN) IPs - mail, DNS, VPN, etc.
# Excluded to keep this a low-noise lead generator, not a list of every MX record.
_NON_WEB_HINTS = frozenset({
    "mail", "smtp", "imap", "pop", "pop3", "mx", "mx1", "mx2", "ns", "ns1", "ns2",
    "ns3", "dns", "ftp", "sftp", "vpn", "mta", "autodiscover", "autoconfig",
    "webmail", "cpanel", "relay", "spf",
})


def _fully_cdn(ips: list[str]) -> bool:
    return bool(ips) and all(cdn_of(ip) for ip in ips)


def detect_cdn(assets: list) -> str | None:
    """The CDN fronting the app, inferred from any fully-CDN-fronted asset."""
    for asset in assets:
        ips = getattr(asset, "ips", []) or []
        if _fully_cdn(ips):
            return cdn_of(ips[0])
    return None


def exposed_origin_ips(ips: list[str]) -> list[str]:
    """Public, non-CDN, non-internal IPs from ``ips`` (candidate directly-reachable origins)."""
    return [ip for ip in ips if cdn_of(ip) is None and classify_ip(ip) is None]


@register
class OriginExposureScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "origin-exposure"
    min_aggressiveness = Aggressiveness.PASSIVE  # reasons over already-resolved IPs; sends nothing

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        assets = getattr(ctx, "assets", []) or []
        cdn = detect_cdn(assets)
        if cdn is None:
            return  # the app is not CDN-fronted; there is no origin to expose

        seen: set[str] = set()
        for asset in assets:
            fqdn = getattr(asset, "fqdn", "") or ""
            label = fqdn.split(".", 1)[0].lower()
            if not fqdn or fqdn in seen or label in _NON_WEB_HINTS:
                continue
            exposed = exposed_origin_ips(getattr(asset, "ips", []) or [])
            if not exposed:
                continue
            seen.add(fqdn)
            yield self._finding(fqdn, exposed, cdn)

    def _finding(self, fqdn: str, exposed: list[str], cdn: str) -> Finding:
        shown = ", ".join(exposed)
        return Finding(
            vuln_type="origin-exposure",
            title=f"Potential origin IP exposure (CDN bypass) at {fqdn}",
            severity=Severity.MEDIUM,
            confidence=Confidence.TENTATIVE,
            url=f"https://{fqdn}",
            description=(
                f"The app is fronted by {cdn}, but the in-scope host '{fqdn}' resolves to a "
                f"public non-{cdn} address ({shown}). If that address serves the application "
                f"directly, an attacker can reach the origin bypassing {cdn}'s WAF, rate limiting, "
                "and geo controls - and origins often expose debug routes or unauthenticated API "
                "versions the edge hides. Verify by requesting the app on that IP with the site's "
                "Host header; if it returns the application, the origin is exposed."
            ),
            remediation=(
                f"Route this host through {cdn} too, and firewall the origin so it only accepts "
                f"connections from {cdn}'s published IP ranges (authenticated origin pull). Do not "
                "expose an unproxied A/AAAA record for a CDN-fronted application."
            ),
            cwe="CWE-668",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                matched_at=fqdn,
                notes=f"resolves to public non-{cdn} address(es): {shown}",
            ),
        )


__all__ = ["OriginExposureScanner", "detect_cdn", "exposed_origin_ips", "SCANNER_NAME"]
