"""Security header analysis (PRD §6.8 Security Headers).

Passive scanner: it inspects response headers already captured during recon
(no extra requests in the common case) and reports missing or weak protections.
Findings are deduped per host since these headers are usually server-wide.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from hydra.core.context import ScanContext
from hydra.core.schemas import Confidence, Finding, Severity
from hydra.scanners.base_scanner import BaseScanner
from hydra.scanners.registry import register
from hydra.utils.logger import get_logger
from hydra.utils.scope import ScopeViolation

logger = get_logger("scanner.headers")

SCANNER_NAME = "security-headers"


def _finding(
    url: str,
    title: str,
    severity: Severity,
    description: str,
    remediation: str,
    cwe: str,
    matched: str | None = None,
) -> Finding:
    return Finding(
        vuln_type="security-headers",
        title=title,
        severity=severity,
        confidence=Confidence.FIRM,
        url=url,
        description=description,
        remediation=remediation,
        cwe=cwe,
        scanner=SCANNER_NAME,
    )


def analyze_headers(url: str, headers: dict[str, str]) -> list[Finding]:
    """Pure analysis of one response's headers -> list of Findings."""
    lower = {k.lower(): v for k, v in headers.items()}
    is_https = urlsplit(url).scheme == "https"
    findings: list[Finding] = []

    csp = lower.get("content-security-policy")
    if not csp:
        findings.append(
            _finding(
                url,
                "Missing Content-Security-Policy header",
                Severity.MEDIUM,
                "No Content-Security-Policy header is set, removing a key defense against "
                "cross-site scripting and data injection.",
                "Define a restrictive CSP, e.g. default-src 'self'; object-src 'none'; "
                "frame-ancestors 'none'.",
                "CWE-693",
            )
        )

    has_frame_ancestors = bool(csp and "frame-ancestors" in csp.lower())
    if "x-frame-options" not in lower and not has_frame_ancestors:
        findings.append(
            _finding(
                url,
                "Missing clickjacking protection (X-Frame-Options / frame-ancestors)",
                Severity.MEDIUM,
                "Neither X-Frame-Options nor a CSP frame-ancestors directive is set; the page "
                "may be framed by an attacker for clickjacking.",
                "Set X-Frame-Options: DENY (or SAMEORIGIN) and/or CSP frame-ancestors 'none'.",
                "CWE-1021",
            )
        )

    if is_https:
        hsts = lower.get("strict-transport-security")
        if not hsts:
            findings.append(
                _finding(
                    url,
                    "Missing Strict-Transport-Security (HSTS) header",
                    Severity.MEDIUM,
                    "HTTPS is served without HSTS, allowing SSL-stripping downgrade attacks.",
                    "Add Strict-Transport-Security: max-age=31536000; includeSubDomains.",
                    "CWE-319",
                )
            )
        elif "max-age" in hsts.lower():
            try:
                max_age = int(hsts.lower().split("max-age=")[1].split(";")[0].strip())
            except (ValueError, IndexError):
                max_age = 0
            if max_age < 15552000:  # < 180 days
                findings.append(
                    _finding(
                        url,
                        "Weak HSTS max-age",
                        Severity.LOW,
                        f"HSTS max-age is {max_age}s, below the recommended 6 months.",
                        "Use max-age=31536000 (1 year) with includeSubDomains.",
                        "CWE-319",
                    )
                )

    if lower.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(
            _finding(
                url,
                "Missing X-Content-Type-Options: nosniff",
                Severity.LOW,
                "Responses can be MIME-sniffed by browsers, enabling content-type confusion.",
                "Set X-Content-Type-Options: nosniff on all responses.",
                "CWE-693",
            )
        )

    if "referrer-policy" not in lower:
        findings.append(
            _finding(
                url,
                "Missing Referrer-Policy header",
                Severity.LOW,
                "Without a Referrer-Policy, full URLs (possibly containing sensitive data) may "
                "leak to third parties via the Referer header.",
                "Set Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).",
                "CWE-200",
            )
        )

    for header, product in (("server", "Server"), ("x-powered-by", "X-Powered-By")):
        value = lower.get(header)
        if value and any(ch.isdigit() for ch in value):
            findings.append(
                _finding(
                    url,
                    f"Version disclosure via {product} header",
                    Severity.INFO,
                    f"The {product} header exposes software/version details: {value!r}.",
                    f"Suppress or genericize the {product} header to reduce fingerprinting.",
                    "CWE-200",
                )
            )

    return findings


@register
class SecurityHeadersScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "security-headers"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        analyzed_hosts: set[str] = set()
        seen: set[tuple[str, str]] = set()

        targets: list[tuple[str, dict[str, str]]] = [
            (ep.url, ep.response_headers)
            for ep in ctx.endpoints
            if ep.response_headers
        ]
        if not targets:
            # No captured headers (e.g. scan without crawl): probe the root once.
            root = ctx.config.target
            if ctx.scope.is_allowed(root):
                try:
                    resp = await ctx.http.get(root)
                    targets = [(root, dict(resp.headers))]
                except (ScopeViolation, httpx.HTTPError) as exc:
                    logger.debug("header probe failed for %s: %s", root, exc)

        for url, headers in targets:
            host = urlsplit(url).netloc
            if host in analyzed_hosts:
                continue
            analyzed_hosts.add(host)
            for finding in analyze_headers(url, headers):
                key = (host, finding.title)
                if key in seen:
                    continue
                seen.add(key)
                yield finding


__all__ = ["SecurityHeadersScanner", "analyze_headers"]
