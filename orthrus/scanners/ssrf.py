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
from orthrus.scanners._cloud_metadata import extract_credentials
from orthrus.scanners._injection import InjectionPoint, injection_points, send, used_url
from orthrus.scanners._payloads import SSRF_METADATA
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

METADATA_PAYLOADS = list(SSRF_METADATA)

# Content signatures only - tokens that appear in actual metadata *responses* but
# NOT in the payload URLs we inject (otherwise a reflected payload false-positives).
# Covers AWS, Azure, GCP, DigitalOcean and Oracle Cloud metadata services.
_METADATA_RE = re.compile(
    # AWS IMDS
    r"ami-id|instance-id|instance-type|local-ipv4|public-keys|block-device-mapping|"
    r"instance-identity|AccessKeyId|SecretAccessKey|"
    # Azure IMDS (instance JSON)
    r"azEnvironment|resourceGroupName|\bvmId\b|"
    # GCP service-account OAuth token response
    r"ya29\.|"
    # DigitalOcean metadata v1.json
    r"droplet_id|"
    # Oracle Cloud Infrastructure
    r"canonicalRegionName|ociAdName",
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
                    creds = extract_credentials(resp.text)
                    if creds is not None:
                        # Escalation: the metadata response leaked live credentials.
                        yield Finding(
                            vuln_type="ssrf",
                            title=(
                                f"SSRF → cloud credential theft ({creds.provider.upper()}) "
                                f"via '{point.param}'"
                            ),
                            severity=Severity.CRITICAL,
                            confidence=Confidence.FIRM,
                            url=used_url(point, payload),
                            parameter=point.param,
                            param_location=point.location,
                            description=(
                                f"Injecting a cloud-metadata URL into '{point.param}' returned live "
                                f"{creds.summary} from the instance metadata service. These are "
                                "short-lived credentials for the instance's role - an attacker can "
                                "use them to act as that role across the cloud account (read storage, "
                                "pivot to other services, escalate), so impact scales with the role's "
                                "permissions. This is full SSRF-to-cloud-takeover, not just metadata "
                                "reachability."
                            ),
                            remediation=(
                                "Enforce IMDSv2 (token-required, hop-limit 1) and disable IMDSv1; "
                                "block 169.254.169.254 and link-local/private ranges at the app and "
                                "network layers; scope the instance role to least privilege; "
                                "allow-list outbound destinations and schemes."
                            ),
                            cwe="CWE-918",
                            scanner=SCANNER_NAME,
                            evidence=Evidence(
                                request_raw=f"{point.param}={payload}",
                                notes=f"{creds.summary}; leaked fields (redacted): {creds.fields}",
                            ),
                        )
                        return
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
