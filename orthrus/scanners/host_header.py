"""Host-header injection / password-reset poisoning scanner (PRD §6 web-class gap).

Many applications build *absolute* URLs - password-reset links, email
confirmation links, redirects, `<script>`/`<link>` src - from the incoming
``Host`` (or ``X-Forwarded-Host``) request header. If that header is trusted, an
attacker can set it to a domain they control:

* **Password-reset poisoning** - the poisoned reset link is emailed to the
  victim; clicking it leaks the secret token to the attacker → account takeover.
* **Web-cache poisoning** - a cached response embeds the attacker's host.
* **Routing-based SSRF** - when the host is used to pick an upstream.

The probe is non-mutating: it sends a GET with a sentinel host in the ``Host``
and ``X-Forwarded-Host`` headers (always through the scope-enforced HttpClient,
which still connects to the real in-scope target) and looks for that sentinel
reflected back as the **authority of an absolute URL** in the body, or as the
host of a redirect ``Location``. Plain substring reflection is deliberately not
enough - the sentinel must appear where it would actually be followed as a URL,
which keeps false positives low.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.host-header")

SCANNER_NAME = "host-header-injection"
MAX_URLS = 40

# A clearly-attacker-controlled sentinel host. It is only ever *sent* as a header
# value and looked for in responses - ORTHRUS never connects to it.
SENTINEL = "orthrus-hhi.example"

# Headers an app might trust when building absolute URLs.
_FORGED_HEADERS = {
    "Host": SENTINEL,
    "X-Forwarded-Host": SENTINEL,
    "X-Forwarded-Server": SENTINEL,
}


def _authority_pattern(sentinel: str) -> re.Pattern[str]:
    # `scheme://sentinel` or scheme-relative `//sentinel`, where the char after
    # the sentinel is a URL delimiter (or end-of-string) - so a longer host such
    # as `sentinel.evil.com` does NOT match.
    return re.compile(
        r"(?:https?:)?//" + re.escape(sentinel) + r"(?=[:/?#\"'\s>]|$)",
        re.IGNORECASE,
    )


def host_reflected_in_url(body: str, sentinel: str = SENTINEL) -> bool:
    """True if ``sentinel`` appears as the host/authority of an absolute URL."""
    return _authority_pattern(sentinel).search(body) is not None


def host_reflected_in_location(location: str, sentinel: str = SENTINEL) -> bool:
    """True if a redirect ``Location`` points at ``sentinel`` as its host."""
    if not location:
        return False
    host = urlsplit(location).hostname
    return host is not None and host == sentinel.lower()


@register
class HostHeaderInjectionScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "host-header-injection"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        found_hosts: set[str] = set()
        seen: set[str] = set()
        candidates = [ctx.config.target, *[ep.url for ep in ctx.endpoints]]
        tested = 0

        for url in candidates:
            if tested >= MAX_URLS:
                break
            norm = url.split("#", 1)[0]
            host = urlsplit(norm).netloc
            if not host or host in found_hosts or norm in seen:
                continue
            if not ctx.scope.is_allowed(norm):
                continue
            seen.add(norm)
            tested += 1

            finding = await self._probe(ctx, norm, host)
            if finding is not None:
                found_hosts.add(host)
                yield finding

    async def _probe(self, ctx: ScanContext, url: str, host: str) -> Finding | None:
        try:
            resp = await ctx.http.get(url, headers=_FORGED_HEADERS, follow_redirects=False)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("host-header probe failed for %s: %s", url, exc)
            return None

        location = resp.headers.get("location", "") or ""
        in_location = host_reflected_in_location(location, SENTINEL)
        in_body = host_reflected_in_url(resp.text, SENTINEL)
        if not (in_location or in_body):
            return None

        where = "the redirect Location header" if in_location else "an absolute URL in the body"
        return Finding(
            vuln_type="host-header-injection",
            title="Host header injection (attacker-controlled host reflected into links/redirects)",
            severity=Severity.MEDIUM,
            confidence=Confidence.FIRM,
            url=url,
            description=(
                f"A sentinel host sent in the 'Host'/'X-Forwarded-Host' request header was "
                f"reflected back into {where}. When the application builds absolute URLs "
                "(password-reset and email-confirmation links, redirects, or script/link src) "
                "from the incoming host header, an attacker can set it to a domain they control. "
                "A victim who clicks the resulting link - e.g. a poisoned password-reset email - "
                "leaks the secret token to the attacker (account takeover); the same primitive "
                "enables web-cache poisoning and, where the host selects an upstream, SSRF."
            ),
            remediation=(
                "Do not trust the incoming Host or X-Forwarded-* headers to build absolute URLs "
                "or routing decisions. Validate Host against an allow-list of expected hostnames "
                "(reject mismatches with 400), build links from a server-side canonical base URL, "
                "and strip X-Forwarded-* at the trust boundary."
            ),
            cwe="CWE-644",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                request_raw=f"Host: {SENTINEL}\nX-Forwarded-Host: {SENTINEL}",
                matched_at=SENTINEL,
                notes=f"forged host reflected into {where}",
            ),
        )


__all__ = [
    "HostHeaderInjectionScanner",
    "host_reflected_in_url",
    "host_reflected_in_location",
    "SENTINEL",
]
