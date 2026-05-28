"""Open redirect scanner (PRD §6.8 Open Redirect).

Injects an attacker-controlled host into parameters and checks whether the
server issues a redirect (Location header) to it. Requests are sent without
following redirects so the raw Location is inspected; nothing off-scope is
actually fetched.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from hydra.core.context import ScanContext
from hydra.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from hydra.scanners._injection import InjectionPoint, injection_points, send, used_url
from hydra.scanners.base_scanner import BaseScanner
from hydra.scanners.registry import register

SCANNER_NAME = "open-redirect"
MAX_POINTS = 120
ATTACKER_HOST = "hydra-redirect.example"

PAYLOADS = [
    f"https://{ATTACKER_HOST}/",
    f"//{ATTACKER_HOST}/",
    f"https:/\\{ATTACKER_HOST}/",
    f"https://{ATTACKER_HOST}%2f..",
]

# Parameter names most likely to drive redirects (tested first; others still tested).
_REDIRECT_HINTS = {
    "url", "next", "redirect", "redirect_uri", "redirecturl", "return", "returnurl",
    "return_url", "dest", "destination", "continue", "to", "target", "goto", "out", "u", "r",
}


def is_open_redirect(location: str | None, attacker_host: str = ATTACKER_HOST) -> bool:
    if not location:
        return False
    normalized = location.replace("\\", "/")
    host = (urlsplit(normalized).hostname or "").lower()
    return host == attacker_host or host.endswith("." + attacker_host)


def _point_sort_key(point: InjectionPoint) -> int:
    return 0 if point.param.lower() in _REDIRECT_HINTS else 1


@register
class OpenRedirectScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "open-redirect"
    min_aggressiveness = Aggressiveness.NORMAL

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        points = sorted(injection_points(ctx), key=_point_sort_key)
        count = 0
        for point in points:
            if count >= MAX_POINTS:
                break
            count += 1
            for payload in PAYLOADS:
                resp = await send(ctx, point, payload, follow_redirects=False)
                if resp is None or not resp.is_redirect:
                    continue
                location = resp.headers.get("location")
                if is_open_redirect(location):
                    yield Finding(
                        vuln_type="open-redirect",
                        title=f"Open redirect via parameter '{point.param}'",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.FIRM,
                        url=used_url(point, payload),
                        parameter=point.param,
                        param_location=point.location,
                        description=(
                            f"Parameter '{point.param}' controls the redirect target. The server "
                            f"redirected to the attacker-controlled host via Location: {location}. "
                            "This enables phishing and OAuth token theft."
                        ),
                        remediation=(
                            "Validate redirect targets against an allow-list of known paths/hosts; "
                            "avoid using user input directly in Location headers."
                        ),
                        cwe="CWE-601",
                        scanner=SCANNER_NAME,
                        evidence=Evidence(
                            request_raw=f"{point.param}={payload}",
                            response_raw=f"Location: {location}",
                            matched_at=location,
                        ),
                    )
                    break


__all__ = ["OpenRedirectScanner", "is_open_redirect"]
