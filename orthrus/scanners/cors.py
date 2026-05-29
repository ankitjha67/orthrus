"""CORS misconfiguration scanner (PRD §6.8 CORS Misconfiguration).

Sends a small set of crafted Origin headers and inspects the reflected
Access-Control-Allow-Origin / -Allow-Credentials response. Detects arbitrary
origin reflection, null-origin trust, and naive suffix matching. Credentialed
reflections are escalated to High.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.cors")

SCANNER_NAME = "cors"
MAX_URLS = 25

ARBITRARY_ORIGIN = "https://orthrus-arbitrary.example"
NULL_ORIGIN = "null"


def analyze_cors(url: str, origin_sent: str, response_headers: dict[str, str]) -> Finding | None:
    """Pure CORS analysis for one probe response -> Finding or None."""
    lower = {k.lower(): v for k, v in response_headers.items()}
    acao = lower.get("access-control-allow-origin")
    if not acao:
        return None
    acac = lower.get("access-control-allow-credentials", "").strip().lower() == "true"

    kind: str | None = None
    if acao == "*" and acac:
        kind = "wildcard Access-Control-Allow-Origin combined with credentials"
    elif acao == origin_sent and origin_sent not in ("*",):
        if origin_sent == NULL_ORIGIN:
            kind = "trusts the 'null' origin"
        else:
            kind = "reflects an arbitrary request Origin"
    else:
        return None

    severity = Severity.HIGH if acac else Severity.MEDIUM
    cred_note = " with credentials allowed" if acac else ""
    return Finding(
        vuln_type="cors",
        title=f"CORS misconfiguration: {kind}{cred_note}",
        severity=severity,
        confidence=Confidence.FIRM,
        url=url,
        description=(
            f"The endpoint {kind}{cred_note}. An attacker-controlled site could send "
            "cross-origin requests and read the responses, exposing data of authenticated users "
            "when credentials are allowed."
        ),
        remediation=(
            "Validate the Origin against an allow-list of trusted origins; never reflect "
            "arbitrary origins, the literal 'null', or combine wildcard ACAO with credentials."
        ),
        cwe="CWE-942",
        scanner=SCANNER_NAME,
        evidence=Evidence(
            request_raw=f"Origin: {origin_sent}",
            response_raw=(
                f"Access-Control-Allow-Origin: {acao}\n"
                f"Access-Control-Allow-Credentials: {str(acac).lower()}"
            ),
            matched_at=acao,
        ),
    )


@register
class CorsScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "cors"

    def _probe_origins(self, host: str) -> list[str]:
        return [ARBITRARY_ORIGIN, NULL_ORIGIN, f"https://{host}.orthrus-attacker.example"]

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen_urls: set[str] = set()
        seen_findings: set[tuple[str, str]] = set()

        candidates = [ctx.config.target, *[ep.url for ep in ctx.endpoints]]
        tested = 0
        for url in candidates:
            if tested >= MAX_URLS:
                break
            norm = url.split("#", 1)[0]
            if norm in seen_urls or not ctx.scope.is_allowed(norm):
                continue
            seen_urls.add(norm)
            tested += 1
            host = urlsplit(norm).hostname or ""

            for origin in self._probe_origins(host):
                try:
                    resp = await ctx.http.get(
                        norm, headers={"Origin": origin}, follow_redirects=False
                    )
                except ScopeViolation:
                    break
                except httpx.HTTPError as exc:
                    logger.debug("cors probe failed for %s: %s", norm, exc)
                    continue

                finding = analyze_cors(norm, origin, dict(resp.headers))
                if finding is None:
                    continue
                key = (host, finding.title)
                if key in seen_findings:
                    continue
                seen_findings.add(key)
                yield finding


__all__ = ["CorsScanner", "analyze_cors"]
