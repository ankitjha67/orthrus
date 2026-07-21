"""CRLF injection / HTTP response splitting scanner.

When user input is copied into a response header (a redirect ``Location``, a
``Set-Cookie``, a cache key) without stripping CR/LF, an attacker can inject
their own headers - or split the response entirely - enabling session fixation,
cache poisoning, and reflected XSS via injected bodies.

The probe sends a value containing ``\\r\\n`` followed by a uniquely-named
sentinel header and cookie. If that header/cookie comes back on the response,
the input reached the header block unescaped - a confirmed split. Detection is
on the *parsed* response headers, so it only fires when the injection actually
took effect (low false positives).
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator, Iterable

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from orthrus.scanners._injection import injection_points, send, used_url
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register

SCANNER_NAME = "crlf-injection"
MAX_PROBES = 80


def _payload(nonce: str) -> str:
    return f"orthrus\r\nX-Orthrus-Crlf: {nonce}\r\nSet-Cookie: ocrlf={nonce}"


def crlf_injected(header_items: Iterable[tuple[str, str]], nonce: str) -> bool:
    """True if the *freshly-injected* nonce survived into a parsed response header.

    Gated on the per-probe ``nonce`` value (not just the sentinel header name), so a
    stale/cached ``X-Orthrus-Crlf`` header from an earlier probe can't be mistaken
    for a live injection. Both injected vectors (``X-Orthrus-Crlf: <nonce>`` and
    ``Set-Cookie: ocrlf=<nonce>``) carry the nonce in their value, so this covers
    every genuine hit.
    """
    return any(nonce in value for _key, value in header_items)


@register
class CrlfInjectionScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "crlf-injection"
    min_aggressiveness = Aggressiveness.NORMAL

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        probes = 0
        for point in injection_points(ctx):
            if probes >= MAX_PROBES:
                break
            probes += 1
            nonce = secrets.token_hex(4)
            resp = await send(ctx, point, _payload(nonce), follow_redirects=False)
            if resp is None or not crlf_injected(dict(resp.headers).items(), nonce):
                continue
            yield Finding(
                vuln_type="crlf-injection",
                title=f"CRLF injection / HTTP response splitting in '{point.param}'",
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                url=used_url(point, "%0d%0a..."),
                parameter=point.param,
                param_location=point.location,
                description=(
                    f"A CRLF sequence injected via '{point.param}' produced an attacker-controlled "
                    "response header (a sentinel header and Set-Cookie appeared in the response). "
                    "This HTTP response splitting enables session fixation, cache poisoning, and "
                    "reflected XSS by smuggling headers or a second response body."
                ),
                remediation=(
                    "Strip or reject CR (%0d) and LF (%0a) in any user input copied into response "
                    "headers (Location, Set-Cookie, etc.); use the framework's header API, which "
                    "rejects embedded newlines, rather than string concatenation."
                ),
                cwe="CWE-113",
                scanner=SCANNER_NAME,
                evidence=Evidence(
                    request_raw=f"{point.param}=orthrus%0d%0aX-Orthrus-Crlf:{nonce}",
                    matched_at=nonce,
                    notes="injected header/cookie reflected in the response header block",
                ),
            )


__all__ = ["CrlfInjectionScanner", "crlf_injected"]
