"""Product fingerprint -> known-CVE matching (PRD §6.8 CVE Matching, version-less).

The NVD CVE matcher (``cve_matcher.py``) needs a *precise* product **version** to
correlate against CPE ranges. High-value enterprise products are frequently
exposed without leaking a clean version string - Oracle WebLogic's admin console
is the classic example: the login page is reachable, the product is unmistakable,
but no version banner is offered. The version-gated matcher therefore skips it
entirely and the most dangerous exposure on the perimeter goes unreported.

This scanner closes that gap. It fingerprints a curated set of products with a
long tail of *known-exploited* (CISA KEV) remote-code-execution CVEs by their
distinctive paths / response markers / headers, and - even with no version -
surfaces the product's notorious CVEs as a prioritised finding, enriched with the
same KEV/EPSS intelligence the NVD matcher uses. When a version *is* recoverable
(e.g. Jenkins' ``X-Jenkins`` header) it is included to sharpen the report.

All probes are non-mutating GETs through the scope-enforced HttpClient.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Iterable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity, Technology
from orthrus.intel.cve_intel import enrich, escalate_severity, summary
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.product-cve")

SCANNER_NAME = "product-cve"
MAX_ORIGINS = 3


@dataclass(frozen=True)
class KnownCve:
    cve_id: str
    score: float
    summary: str


@dataclass(frozen=True)
class ProductSignature:
    key: str
    name: str
    category: str
    cwe: str
    base_severity: Severity
    remediation: str
    cves: tuple[KnownCve, ...]
    probe_paths: tuple[str, ...] = ()
    body_markers: tuple[str, ...] = ()
    # (header-name, substring) - both lowercased at match time.
    header_markers: tuple[tuple[str, str], ...] = ()
    # Regexes whose first group is the version; tried against headers + body.
    version_patterns: tuple[str, ...] = ()
    # Substrings matched against already-fingerprinted Technology.name values.
    tech_keywords: tuple[str, ...] = field(default=())


# --- curated knowledge base: products with a deep bench of KEV-listed RCE CVEs ---
PRODUCTS: tuple[ProductSignature, ...] = (
    ProductSignature(
        key="oracle-weblogic",
        name="Oracle WebLogic Server",
        category="app-server",
        cwe="CWE-502",
        base_severity=Severity.CRITICAL,
        remediation=(
            "Apply the latest Oracle Critical Patch Update for WebLogic. Block external access "
            "to the admin console (/console), the T3/T3S and IIOP protocols, and /wls-wsat; "
            "restrict management interfaces to a trusted network."
        ),
        cves=(
            KnownCve("CVE-2020-14882", 9.8, "Admin console unauthenticated RCE via path traversal"),
            KnownCve("CVE-2020-14883", 7.2, "Admin console RCE (chained with CVE-2020-14882)"),
            KnownCve("CVE-2017-10271", 9.8, "WLS-WSAT XML deserialization RCE"),
            KnownCve("CVE-2019-2725", 9.8, "wls9-async / WLS-WSAT deserialization RCE"),
            KnownCve("CVE-2018-2628", 9.8, "T3 protocol deserialization RCE"),
            KnownCve("CVE-2020-2551", 9.8, "IIOP protocol deserialization RCE"),
            KnownCve("CVE-2023-21839", 7.5, "T3/IIOP JNDI injection RCE"),
        ),
        probe_paths=(
            "/console/login/LoginForm.jsp",
            "/console/",
            "/wls-wsat/CoordinatorPortType",
        ),
        body_markers=(
            "WebLogic Server",
            "Oracle WebLogic",
            "Welcome to the WebLogic",
            "console/login/LoginForm.jsp",
        ),
        header_markers=(("server", "weblogic"),),
        version_patterns=(
            r"WebLogic Server[^\d]{0,40}(\d+\.\d+(?:\.\d+){0,3})",
            r"Oracle WebLogic Server[^\d]{0,40}(\d+\.\d+(?:\.\d+){0,3})",
        ),
        tech_keywords=("weblogic",),
    ),
    ProductSignature(
        key="atlassian-confluence",
        name="Atlassian Confluence",
        category="wiki",
        cwe="CWE-74",
        base_severity=Severity.CRITICAL,
        remediation=(
            "Upgrade Confluence to a fixed release and review Atlassian security advisories. "
            "Restrict administrative endpoints and place the instance behind authentication / VPN."
        ),
        cves=(
            KnownCve("CVE-2022-26134", 9.8, "OGNL injection - unauthenticated RCE"),
            KnownCve("CVE-2023-22515", 10.0, "Broken access control - privilege escalation"),
        ),
        probe_paths=("/", "/login.action"),
        body_markers=(
            'name="ajs-version-number"',
            "Confluence",
            "com.atlassian.confluence",
            "confluence-base-url",
        ),
        version_patterns=(
            r'name="ajs-version-number"\s+content="([\d.]+)"',
            r"Confluence[^\d]{0,20}(\d+\.\d+\.\d+)",
        ),
        tech_keywords=("confluence",),
    ),
    ProductSignature(
        key="jenkins",
        name="Jenkins",
        category="ci",
        cwe="CWE-22",
        base_severity=Severity.HIGH,
        remediation=(
            "Upgrade Jenkins to the latest LTS, disable the CLI if unused, enable security "
            "(authentication + authorization), and never expose the controller to the internet."
        ),
        cves=(
            KnownCve("CVE-2024-23897", 9.8, "CLI args4j arbitrary file read -> RCE"),
            KnownCve("CVE-2018-1000861", 9.8, "Stapler routing remote code execution"),
        ),
        probe_paths=("/login", "/"),
        body_markers=("Jenkins-Crumb", "Dashboard [Jenkins]", "jenkins-session"),
        header_markers=(("x-jenkins", ""),),
        version_patterns=(r"(?i)x-jenkins:\s*([\d.]+)", r"Jenkins ver\.?\s*([\d.]+)"),
        tech_keywords=("jenkins",),
    ),
    ProductSignature(
        key="apache-solr",
        name="Apache Solr",
        category="search",
        cwe="CWE-94",
        base_severity=Severity.CRITICAL,
        remediation=(
            "Upgrade Solr and the bundled log4j, disable the Velocity response writer / params "
            "resource loader, and bind the admin UI to localhost or behind authentication."
        ),
        cves=(
            KnownCve("CVE-2019-17558", 8.5, "Velocity template injection RCE (params resource loader)"),
            KnownCve("CVE-2021-44228", 10.0, "Log4Shell - log4j2 JNDI lookup RCE"),
        ),
        probe_paths=("/solr/", "/solr/admin/cores"),
        body_markers=("Solr Admin", "solr-admin", '"responseHeader"', "Apache SOLR"),
        version_patterns=(r'"solr-spec-version"\s*:\s*"([\d.]+)"', r"Solr/([\d.]+)"),
        tech_keywords=("solr",),
    ),
)


def _versionless_text(headers: dict[str, str], body: str) -> str:
    """Synthetic blob (header lines + body) for version-regex matching."""
    header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items())
    return header_blob + "\n" + body


def match_signature(
    sig: ProductSignature, headers: dict[str, str], body: str, status: int
) -> bool:
    """True if a response carries a distinctive marker for this product.

    Requires a positive signal (header marker or body marker); a bare status
    code is never enough, so a generic catch-all page cannot false-positive.
    """
    lower_headers = {k.lower(): (v or "").lower() for k, v in headers.items()}
    for hname, substr in sig.header_markers:
        value = lower_headers.get(hname.lower())
        if value is not None and substr.lower() in value:
            return True
    if status >= 500:  # body markers on a server-error page are unreliable
        return False
    low_body = body.lower()
    return any(marker.lower() in low_body for marker in sig.body_markers)


def extract_version(sig: ProductSignature, headers: dict[str, str], body: str) -> str | None:
    """First version captured by any of the product's version regexes, else None."""
    blob = _versionless_text(headers, body)
    for pattern in sig.version_patterns:
        match = re.search(pattern, blob)
        if match:
            return match.group(1)
    return None


def tech_match(sig: ProductSignature, technologies: Iterable[Technology]) -> tuple[bool, str | None]:
    """Match the product against already-fingerprinted technologies (recon)."""
    for tech in technologies:
        name = (tech.name or "").lower()
        if any(keyword in name for keyword in sig.tech_keywords):
            return True, tech.version
    return False, None


def origins_from(target: str, endpoint_urls: Iterable[str]) -> list[str]:
    """Distinct ``scheme://host`` origins from the target + discovered endpoints."""
    seen: list[str] = []
    for url in (target, *endpoint_urls):
        parts = urlsplit(url)
        if parts.scheme and parts.netloc:
            origin = f"{parts.scheme}://{parts.netloc}"
            if origin not in seen:
                seen.append(origin)
    return seen


@register
class ProductCveScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "cve"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        origins = origins_from(ctx.config.target, [ep.url for ep in ctx.endpoints])[:MAX_ORIGINS]
        all_techs = [tech for asset in ctx.assets for tech in asset.technologies]
        emitted: set[tuple[str, str]] = set()

        for origin in origins:
            cache: dict[str, httpx.Response | None] = {}
            for sig in PRODUCTS:
                if (origin, sig.key) in emitted:
                    continue

                detected = False
                version: str | None = None
                evidence_at = ""

                # 1) Leverage recon's existing fingerprints first (no extra request).
                hit, tech_version = tech_match(sig, all_techs)
                if hit:
                    detected = True
                    version = tech_version
                    evidence_at = "recon fingerprint"

                # 2) Otherwise probe the product's distinctive paths.
                if not detected:
                    for path in sig.probe_paths:
                        url = origin + path
                        if not ctx.scope.is_allowed(url):
                            continue
                        resp = cache.get(path)
                        if path not in cache:
                            resp = await self._get(ctx, url)
                            cache[path] = resp
                        if resp is None:
                            continue
                        headers = dict(resp.headers)
                        if match_signature(sig, headers, resp.text, resp.status_code):
                            detected = True
                            version = extract_version(sig, headers, resp.text)
                            evidence_at = path
                            break

                if not detected:
                    continue
                emitted.add((origin, sig.key))
                yield self._finding(origin, sig, version, evidence_at)

    async def _get(self, ctx: ScanContext, url: str) -> httpx.Response | None:
        try:
            return await ctx.http.get(url, follow_redirects=False)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("product-cve probe failed for %s: %s", url, exc)
            return None

    def _finding(
        self, origin: str, sig: ProductSignature, version: str | None, evidence_at: str
    ) -> Finding:
        intels = {cve.cve_id: enrich(cve.cve_id) for cve in sig.cves}
        kev_ids = [cve.cve_id for cve in sig.cves if intels[cve.cve_id].kev]
        worst = max(sig.cves, key=lambda c: c.score)
        worst_intel = intels[worst.cve_id]
        severity = escalate_severity(sig.base_severity, worst_intel)

        ver_str = f" {version}" if version else " (version not disclosed)"
        kev_tag = f" [{len(kev_ids)} CISA-KEV]" if kev_ids else ""

        cve_lines = []
        for cve in sig.cves:
            tag = summary(intels[cve.cve_id])
            cve_lines.append(
                f"  - {cve.cve_id} (CVSS {cve.score}): {cve.summary}" + (f" {tag}" if tag else "")
            )
        cve_block = "\n".join(cve_lines)

        # Version-confirmed detection is firm; a version-less product match flags a
        # real exposure but each CVE's applicability still depends on the build.
        confidence = Confidence.FIRM if version else Confidence.TENTATIVE

        return Finding(
            vuln_type="cve",
            title=f"Exposed {sig.name}{ver_str} - {len(sig.cves)} known-exploited CVE(s){kev_tag}",
            severity=severity,
            confidence=confidence,
            url=origin,
            description=(
                f"{sig.name} was fingerprinted at {origin} ({evidence_at}). This product family "
                f"has a long history of unauthenticated remote-code-execution CVEs, several on the "
                f"CISA Known Exploited Vulnerabilities catalog. "
                + (
                    f"The running version ({version}) was recovered; "
                    if version
                    else "No version banner was exposed, so per-CVE applicability must be "
                    "confirmed against the running build, but the exposure itself is real. "
                )
                + "Known high-impact CVEs for this product:\n"
                + cve_block
            ),
            remediation=sig.remediation,
            cwe=sig.cwe,
            cvss_score=worst.score,
            scanner=SCANNER_NAME,
            evidence=Evidence(
                matched_at=evidence_at,
                notes=(
                    f"{sig.name} detected"
                    + (f" v{version}" if version else " (no version)")
                    + (f"; KEV: {', '.join(kev_ids)}" if kev_ids else "")
                ),
            ),
        )


__all__ = [
    "ProductCveScanner",
    "ProductSignature",
    "KnownCve",
    "PRODUCTS",
    "match_signature",
    "extract_version",
    "tech_match",
    "origins_from",
]
