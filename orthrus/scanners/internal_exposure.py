"""Internal-IP exposure: a public DNS record that resolves to a non-routable address.

When an in-scope hostname resolves to an RFC1918 / loopback / link-local / CGNAT /
IPv6 unique-local / cloud-metadata IP, the DNS record leaks internal network
topology. It is a strong lead for SSRF pivoting (the internal host is named and
reachable from inside), a dangling internal record (potential takeover), or a
staging/admin surface that was never meant to be public. This is m0chan's
``FindInternalIPSubdomains.sh`` turned into a first-class finding.

Passive: it reads the IPs already resolved during recon (``ctx.assets``) and
classifies them - it sends no traffic of its own.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.ip_classify import classify_ip
from orthrus.utils.logger import get_logger

logger = get_logger("scanner.internal-exposure")

SCANNER_NAME = "internal-exposure"


@register
class InternalExposureScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "internal-ip-disclosure"
    min_aggressiveness = Aggressiveness.PASSIVE  # reads already-resolved IPs; sends nothing

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        for asset in getattr(ctx, "assets", []) or []:
            fqdn = getattr(asset, "fqdn", "") or ""
            if not fqdn or fqdn in seen:
                continue
            hits = [(ip, cat) for ip in getattr(asset, "ips", []) if (cat := classify_ip(ip))]
            if not hits:
                continue
            seen.add(fqdn)
            yield self._finding(fqdn, hits)

    def _finding(self, fqdn: str, hits: list[tuple[str, str]]) -> Finding:
        categories = {cat for _ip, cat in hits}
        metadata = "cloud-metadata" in categories
        shown = ", ".join(f"{ip} ({cat})" for ip, cat in hits)
        severity = Severity.HIGH if metadata else Severity.MEDIUM
        meta_note = (
            " One record points at a cloud metadata address (169.254.169.254-class) - a "
            "classic SSRF lure and a sign of a copied/misconfigured record."
            if metadata else ""
        )
        return Finding(
            vuln_type="internal-ip-disclosure",
            title=f"Public hostname resolves to an internal address: {fqdn}",
            severity=severity,
            confidence=Confidence.FIRM,
            url=f"https://{fqdn}",
            description=(
                f"The in-scope hostname '{fqdn}' resolves to non-routable address(es) [{shown}]. "
                "A public DNS record pointing at internal space leaks internal network topology "
                "and commonly marks a staging/admin host, a dangling internal record, or an "
                f"SSRF-reachable internal service named in DNS.{meta_note}"
            ),
            remediation=(
                "Remove public DNS records that point at internal addresses; serve internal "
                "hosts from a split-horizon/private zone. Review whether the named host is meant "
                "to be reachable and whether it is referenced by any SSRF-capable feature."
            ),
            cwe="CWE-200",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                matched_at=fqdn,
                notes=f"resolved to internal address(es): {shown}",
            ),
        )


__all__ = ["InternalExposureScanner", "SCANNER_NAME"]
