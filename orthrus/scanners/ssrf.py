"""Server-side request forgery scanner (PRD §6.4).

Primary detection is out-of-band: inject a per-token callback URL into each
parameter, then poll the callback server for a hit (the target making the
request server-side). Secondary, callback-free detection injects cloud-metadata
URLs and matches their signatures in the response. OOB requires a reachable
callback server; without one, only the response-based check runs.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.scanners._injection import InjectionPoint, injection_points, send, used_url
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger

logger = get_logger("scanner.ssrf")

SCANNER_NAME = "ssrf"
MAX_POINTS = 60
POLL_DELAY = 3.0

URL_HINTS = {
    "url", "uri", "link", "src", "source", "dest", "destination", "redirect", "callback",
    "webhook", "image", "img", "file", "path", "feed", "proxy", "host", "domain", "target",
    "fetch", "load", "u", "next", "data", "reference", "ref",
}

METADATA_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
]

# Content signatures only — tokens that appear in actual metadata *responses* but
# NOT in the payload URLs we inject (otherwise a reflected payload false-positives).
_METADATA_RE = re.compile(
    r"ami-id|instance-id|instance-type|local-ipv4|public-keys|block-device-mapping|"
    r"instance-identity|AccessKeyId|SecretAccessKey",
    re.IGNORECASE,
)


def detect_metadata_leak(body: str) -> bool:
    return bool(_METADATA_RE.search(body))


def _ordered_points(ctx: ScanContext) -> list[InjectionPoint]:
    points = list(injection_points(ctx))
    points.sort(key=lambda p: 0 if p.param.lower() in URL_HINTS else 1)
    return points[:MAX_POINTS]


@register
class SsrfScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "ssrf"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        points = _ordered_points(ctx)

        async for finding in self._response_based(ctx, points):
            yield finding

        if ctx.callback is None:
            logger.debug("ssrf: no callback server; OOB detection skipped")
            return

        oob_jobs: list[tuple[InjectionPoint, str, str]] = []
        for point in points:
            token, url = ctx.callback.new_token()
            resp = await send(ctx, point, url)
            if resp is not None:
                oob_jobs.append((point, token, url))

        if not oob_jobs:
            return
        await asyncio.sleep(POLL_DELAY)

        for point, token, url in oob_jobs:
            interactions = await ctx.callback.poll(token)
            if not interactions:
                continue
            hit = interactions[0]
            await ctx.store.add_callback(
                token, hit.protocol, hit.source_ip, {"path": hit.path, "method": hit.method}
            )
            yield Finding(
                vuln_type="ssrf",
                title=f"Server-side request forgery via '{point.param}' (out-of-band)",
                severity=Severity.HIGH,
                confidence=Confidence.FIRM,
                url=used_url(point, url),
                parameter=point.param,
                param_location=point.location,
                description=(
                    f"The server fetched an attacker-supplied URL placed in '{point.param}'. The "
                    f"callback server received a {hit.protocol.upper()} request from {hit.source_ip}. "
                    "SSRF can reach internal services and cloud metadata."
                ),
                remediation=(
                    "Validate and allow-list outbound URLs/hosts, block link-local and private "
                    "ranges, disable unused URL schemes, and require metadata service v2 (IMDSv2)."
                ),
                cwe="CWE-918",
                scanner=SCANNER_NAME,
                evidence=Evidence(
                    request_raw=f"{point.param}={url}",
                    notes=f"OOB callback from {hit.source_ip} (token {token})",
                    matched_at=hit.source_ip,
                ),
            )

    async def _response_based(
        self, ctx: ScanContext, points: list[InjectionPoint]
    ) -> AsyncIterator[Finding]:
        for point in points:
            if point.param.lower() not in URL_HINTS:
                continue
            for payload in METADATA_PAYLOADS:
                resp = await send(ctx, point, payload)
                if resp is None:
                    continue
                if detect_metadata_leak(resp.text):
                    yield Finding(
                        vuln_type="ssrf",
                        title=f"SSRF to cloud metadata via '{point.param}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.FIRM,
                        url=used_url(point, payload),
                        parameter=point.param,
                        param_location=point.location,
                        description=(
                            f"Injecting a cloud-metadata URL into '{point.param}' returned metadata "
                            "content, indicating SSRF with access to the instance metadata service."
                        ),
                        remediation=(
                            "Block requests to 169.254.169.254 and link-local ranges; enforce "
                            "IMDSv2; allow-list outbound destinations."
                        ),
                        cwe="CWE-918",
                        scanner=SCANNER_NAME,
                        evidence=Evidence(
                            request_raw=f"{point.param}={payload}",
                            notes="cloud metadata signature in response",
                        ),
                    )
                    return


__all__ = ["SsrfScanner", "detect_metadata_leak"]
