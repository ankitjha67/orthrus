"""Client-side prototype pollution scanner (PRD §6.8 Prototype Pollution).

Injects ``__proto__`` / ``constructor.prototype`` payloads via query parameters
and the URL fragment, loads the page in the headless browser, and checks whether
``Object.prototype`` was polluted with our marker. A polluted prototype proves a
vulnerable client-side merge. Browser-gated; findings are CONFIRMED on detection.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, HttpMethod, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger

logger = get_logger("scanner.prototype-pollution")

SCANNER_NAME = "prototype-pollution"
MAX_PROBES = 30


def _payloads(prop: str, marker: str) -> list[str]:
    return [
        f"__proto__[{prop}]={marker}",
        f"__proto__.{prop}={marker}",
        f"constructor[prototype][{prop}]={marker}",
        f"constructor.prototype.{prop}={marker}",
    ]


@register
class PrototypePollutionScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "prototype-pollution"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        if ctx.browser is None:
            logger.debug("prototype-pollution: no browser engine; skipping")
            return

        probes = 0
        seen_paths: set[str] = set()
        for endpoint in ctx.endpoints:
            if endpoint.method != HttpMethod.GET or probes >= MAX_PROBES:
                continue
            base = endpoint.url.split("#", 1)[0]
            path = urlsplit(base).path
            if path in seen_paths:
                continue
            seen_paths.add(path)
            probes += 1

            prop = "hpp" + secrets.token_hex(3)
            marker = secrets.token_hex(4)
            for raw in _payloads(prop, marker):
                sep = "&" if urlsplit(base).query else "?"
                for target in (f"{base}{sep}{raw}", f"{base}#{raw}"):
                    if not ctx.scope.is_allowed(target):
                        continue
                    value = await ctx.browser.evaluate_on(
                        target, f"() => (Object.prototype['{prop}'] || null)"
                    )
                    if value == marker:
                        yield Finding(
                            vuln_type="prototype-pollution",
                            title="Client-side prototype pollution",
                            severity=Severity.HIGH,
                            confidence=Confidence.CONFIRMED,
                            url=target,
                            description=(
                                "A payload polluted Object.prototype in the browser "
                                f"(Object.prototype.{prop} === '{marker}'). A vulnerable client-side "
                                "merge can be abused for DOM XSS, auth bypass, or RCE in gadgets."
                            ),
                            remediation=(
                                "Reject __proto__/constructor/prototype keys when merging untrusted "
                                "input; use Map or Object.create(null); freeze Object.prototype."
                            ),
                            cwe="CWE-1321",
                            scanner=SCANNER_NAME,
                            evidence=Evidence(request_raw=target, matched_at=marker),
                        )
                        return


__all__ = ["PrototypePollutionScanner"]
