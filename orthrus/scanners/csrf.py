"""CSRF scanner (PRD §6.8 CSRF).

Passive: inspects discovered POST forms for the presence of an anti-CSRF token
field. State-changing forms with no recognizable token are flagged. Reliable
confirmation (constructing a cross-origin request that changes state) is a
Phase-4 exploitation concern.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, HttpMethod, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register

SCANNER_NAME = "csrf"

_TOKEN_HINTS = (
    "csrf", "xsrf", "token", "authenticity_token", "__requestverificationtoken",
    "nonce", "_token", "csrfmiddlewaretoken",
)


def form_has_csrf_token(param_names: list[str]) -> bool:
    lowered = [n.lower() for n in param_names]
    return any(any(hint in name for hint in _TOKEN_HINTS) for name in lowered)


@register
class CsrfScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "csrf"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        for endpoint in ctx.endpoints:
            if endpoint.method != HttpMethod.POST or endpoint.source != "form":
                continue
            param_names = [p.name for p in endpoint.params]
            if not param_names or form_has_csrf_token(param_names):
                continue
            path = urlsplit(endpoint.url).path
            key = f"{urlsplit(endpoint.url).netloc}{path}"
            if key in seen:
                continue
            seen.add(key)
            yield Finding(
                vuln_type="csrf",
                title="POST form without anti-CSRF token",
                severity=Severity.MEDIUM,
                confidence=Confidence.TENTATIVE,
                url=endpoint.url,
                description=(
                    "A state-changing POST form was found with no recognizable anti-CSRF token "
                    f"field (fields: {', '.join(param_names)}). If the session relies on cookies "
                    "without SameSite protection, the action may be forgeable cross-site."
                ),
                remediation=(
                    "Include a per-session/per-request anti-CSRF token in state-changing forms and "
                    "validate it server-side; set session cookies SameSite=Lax or Strict."
                ),
                cwe="CWE-352",
                scanner=SCANNER_NAME,
                evidence=Evidence(notes=f"form fields: {', '.join(param_names)}"),
            )


__all__ = ["CsrfScanner", "form_has_csrf_token"]
