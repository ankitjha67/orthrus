"""Subdomain takeover scanner.

A subdomain whose DNS still points at a de-provisioned third-party service (S3,
GitHub Pages, Heroku, Fastly, …) can be claimed by an attacker, who then serves
content from your domain. ORTHRUS fetches the root of each in-scope host and
matches the response against a fingerprint table of "unclaimed service" pages.

The detection is purely the response fingerprint (the DNS/CNAME context is what
makes it exploitable); fingerprints are exact provider phrases to keep false
positives low.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit, urlunsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.subdomain-takeover")

SCANNER_NAME = "subdomain-takeover"
MAX_HOSTS = 25

# (service, distinctive "unclaimed" response phrases). Lowercased at match time.
TAKEOVER_FINGERPRINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("GitHub Pages", ("there isn't a github pages site here", "for root urls (like http://example.com/)")),
    ("AWS S3", ("nosuchbucket", "the specified bucket does not exist")),
    ("Heroku", ("no such app", "herokucdn.com/error-pages/no-such-app.html")),
    ("Fastly", ("fastly error: unknown domain",)),
    ("Shopify", ("sorry, this shop is currently unavailable",)),
    ("Bitbucket", ("repository not found", "the page you have requested does not exist")),
    ("Surge.sh", ("project not found",)),
    ("Cargo", ("404 not found", "if you're moving your domain away from cargo")),
    ("Pantheon", ("the gods are wise, but do not know of the site which you seek",)),
    ("Tumblr", ("whatever you were looking for doesn't currently exist at this address",)),
    ("Zendesk", ("help center closed", "this help center no longer exists")),
    ("Unbounce", ("the requested url was not found on this server",)),
    ("Ghost", ("the thing you were looking for is no longer here",)),
    ("Microsoft Azure", ("404 web site not found", "error 404 - web app not found")),
    ("Acquia", ("web site not found",)),
    ("Readme.io", ("project doesnt exist... yet!",)),
    ("HelpScout", ("no settings were found for this company",)),
    ("AWS/Cloud", ("the specified bucket does not exist",)),
)


def match_takeover_fingerprint(body: str) -> str | None:
    """Return the service name if the body matches an 'unclaimed service' page."""
    low = body.lower()
    for service, phrases in TAKEOVER_FINGERPRINTS:
        if any(p in low for p in phrases):
            return service
    return None


@register
class SubdomainTakeoverScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "subdomain-takeover"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen_hosts: set[str] = set()
        candidates = [ctx.config.target, *[ep.url for ep in ctx.endpoints]]

        for url in candidates:
            parts = urlsplit(url.split("#", 1)[0])
            if not parts.netloc or parts.netloc in seen_hosts:
                continue
            if len(seen_hosts) >= MAX_HOSTS:
                break
            root = urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
            if not ctx.scope.is_allowed(root):
                continue
            seen_hosts.add(parts.netloc)

            try:
                resp = await ctx.http.get(root, follow_redirects=True)
            except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
                logger.debug("subdomain-takeover probe failed for %s: %s", root, exc)
                continue

            service = match_takeover_fingerprint(resp.text)
            if service is None:
                continue
            yield Finding(
                vuln_type="subdomain-takeover",
                title=f"Possible subdomain takeover ({service}) at {parts.netloc}",
                severity=Severity.HIGH,
                confidence=Confidence.TENTATIVE,
                url=root,
                description=(
                    f"The host {parts.netloc} serves {service}'s 'unclaimed resource' page. If its "
                    "DNS record still points at a de-provisioned third-party resource, an attacker "
                    "can register that resource and serve arbitrary content from your domain — "
                    "enabling phishing, cookie theft, and OAuth/redirect abuse. Confirm the "
                    "dangling CNAME/ALIAS before reporting."
                ),
                remediation=(
                    "Remove or repoint the dangling DNS record, or re-claim the third-party "
                    "resource. Audit DNS for records pointing at unprovisioned services."
                ),
                cwe="CWE-350",
                scanner=SCANNER_NAME,
                evidence=Evidence(
                    matched_at=service,
                    notes=f"{service} unclaimed-resource fingerprint matched on host root",
                ),
            )


__all__ = ["SubdomainTakeoverScanner", "match_takeover_fingerprint", "TAKEOVER_FINGERPRINTS"]
