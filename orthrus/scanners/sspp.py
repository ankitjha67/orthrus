"""Server-side prototype pollution scanner.

Sends a JSON body that pollutes ``__proto__`` (or ``constructor.prototype``) with
a unique sentinel property, then issues a *fresh* benign request. If the sentinel
now appears in that fresh response, the property leaked onto a new object via the
prototype — confirming server-side prototype pollution (Node.js et al.). The
differential check (clean before, polluted after) avoids the echo false positive
of merely reflecting the input back.

Prototype pollution is a JS-runtime class; against a non-Node target the probe
simply finds nothing.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import (
    Aggressiveness,
    Confidence,
    Evidence,
    Finding,
    ParamLocation,
    Severity,
)
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.sspp")

SCANNER_NAME = "server-side-prototype-pollution"
MAX_ENDPOINTS = 15


def _is_json_candidate(url: str, param_locations: tuple[ParamLocation, ...]) -> bool:
    if "/api" in urlsplit(url).path.lower():
        return True
    return ParamLocation.JSON in param_locations


def pollution_confirmed(before_body: str, after_body: str, sentinel: str) -> bool:
    """True if a clean request started returning the polluted sentinel."""
    return sentinel not in before_body and sentinel in after_body


@register
class ServerSidePrototypePollutionScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "prototype-pollution"
    min_aggressiveness = Aggressiveness.NORMAL

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        tested = 0
        for ep in ctx.endpoints:
            url = ep.url.split("#", 1)[0]
            locs = tuple(p.location for p in getattr(ep, "params", []))
            if url in seen or not _is_json_candidate(url, locs):
                continue
            if not ctx.scope.is_allowed(url):
                continue
            seen.add(url)
            if tested >= MAX_ENDPOINTS:
                break
            tested += 1

            finding = await self._probe(ctx, url)
            if finding is not None:
                yield finding

    async def _probe(self, ctx: ScanContext, url: str) -> Finding | None:
        nonce = secrets.token_hex(4)
        sentinel = f"orthrusPP{nonce}"
        benign = {"orthrus": "x"}

        before = await self._post_json(ctx, url, benign)
        if before is None or sentinel in before.text:
            return None
        # Pollute the prototype with the sentinel property.
        await self._post_json(ctx, url, {"__proto__": {sentinel: "polluted"}, **benign})
        await self._post_json(
            ctx, url, {"constructor": {"prototype": {sentinel: "polluted"}}, **benign}
        )
        after = await self._post_json(ctx, url, benign)
        if after is None or not pollution_confirmed(before.text, after.text, sentinel):
            return None

        return Finding(
            vuln_type="prototype-pollution",
            title="Server-side prototype pollution (__proto__ persisted to new objects)",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            url=url,
            description=(
                "A sentinel property injected via '__proto__'/'constructor.prototype' appeared in a "
                "subsequent clean response, proving it leaked onto a freshly-created object through "
                "the prototype. Server-side prototype pollution can escalate to denial of service, "
                "property-injection logic bypass, and (with a suitable gadget) remote code execution."
            ),
            remediation=(
                "Reject or strip '__proto__'/'constructor'/'prototype' keys before merging untrusted "
                "JSON; use Map or Object.create(null) for user-controlled dictionaries, freeze "
                "Object.prototype, and validate input against a strict schema."
            ),
            cwe="CWE-1321",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                request_raw='{"__proto__":{"' + sentinel + '":"polluted"}}',
                matched_at=sentinel,
                notes="sentinel appeared in a fresh request after pollution (differential check)",
            ),
        )

    async def _post_json(self, ctx: ScanContext, url: str, body: dict) -> httpx.Response | None:
        try:
            return await ctx.http.request("POST", url, json=body, follow_redirects=True)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("sspp probe failed for %s: %s", url, exc)
            return None


__all__ = ["ServerSidePrototypePollutionScanner", "pollution_confirmed"]
