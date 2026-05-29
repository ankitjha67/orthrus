"""Reflected XSS scanner (PRD §6.3 Cross-Site Scripting).

Detection only — exploitation/confirmation (callback or DOM execution) is the
Phase-4 job of exploits/xss_confirm.py. This injects a marker-wrapped probe so
that, regardless of how surrounding characters are handled, we can tell exactly
which of < > " ' are reflected unencoded and infer the injection context.
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
    Endpoint,
    Evidence,
    Finding,
    HttpMethod,
    ParamLocation,
    Severity,
)
from orthrus.scanners._payloads import xss_execution_payloads
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.encoding import with_query_param
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.xss")

SCANNER_NAME = "reflected-xss"
PROBE_CHARS = ("<", ">", '"', "'")
MAX_TESTS = 300


def build_payload(marker: str) -> str:
    """marker + each probe char wrapped by the marker, so survival is unambiguous."""
    return marker + "".join(f"{c}{marker}" for c in PROBE_CHARS)


def execution_payloads(marker: str) -> list[str]:
    """Browser-executing payloads that set ``window['__hx_<marker>']=1``.

    Delegates to the shared XSS corpus (orthrus.scanners._payloads). Each payload
    sets a *marker-namespaced* global so detection survives pages that render
    many payloads (stored XSS) — no last-write-wins clash and no alert()-driven
    dialog storms. Covers script/event-handler/SVG/iframe contexts, several
    tag-breakout prefixes, and a context-spanning polyglot.
    """
    return xss_execution_payloads(marker)


def detect_reflection(marker: str, body: str) -> tuple[bool, set[str]]:
    """Return (was the marker reflected, set of probe chars reflected unencoded)."""
    reflected = marker in body
    survived = {c for c in PROBE_CHARS if f"{marker}{c}{marker}" in body}
    return reflected, survived


def is_html_context(content_type: str | None) -> bool:
    """Whether a reflected payload could execute as HTML in this response.

    Reflecting ``<script>`` into an ``application/json`` (or other non-HTML)
    response is not XSS — browsers don't render it as markup — so we only treat
    HTML-ish content types (and a missing/empty type, which can be sniffed) as
    an XSS context. This suppresses false positives on JSON API echoes.
    """
    if not content_type:
        return True  # no/empty type: may be content-sniffed as HTML
    ct = content_type.lower()
    if "json" in ct:
        return False
    return "html" in ct or "xml" in ct or ct.startswith("text/")


def classify(survived: set[str]) -> tuple[Severity, Confidence, str] | None:
    if "<" in survived and ">" in survived:
        return Severity.HIGH, Confidence.FIRM, "HTML body (tag injection possible)"
    if '"' in survived or "'" in survived:
        return Severity.MEDIUM, Confidence.TENTATIVE, "quoted attribute / JS string (breakout possible)"
    return None


def _snippet(marker: str, body: str) -> str | None:
    idx = body.find(marker)
    if idx == -1:
        return None
    start = max(0, idx - 40)
    end = min(len(body), idx + 80)
    return body[start:end].replace("\n", " ")


def _make_finding(
    url: str, param: str, location: ParamLocation, payload: str, body: str, survived: set[str]
) -> Finding | None:
    verdict = classify(survived)
    if verdict is None:
        return None
    severity, confidence, context = verdict
    return Finding(
        vuln_type="xss",
        title=f"Reflected XSS via parameter '{param}'",
        severity=severity,
        confidence=confidence,
        url=url,
        parameter=param,
        param_location=location,
        description=(
            f"User input in parameter '{param}' is reflected into the response with the "
            f"characters {sorted(survived)} unencoded. Context: {context}. This indicates a "
            "reflected cross-site scripting vulnerability."
        ),
        remediation=(
            "Contextually output-encode reflected user input (HTML entity encoding in HTML "
            "context, attribute/JS encoding as appropriate) and apply a strict CSP."
        ),
        cwe="CWE-79",
        scanner=SCANNER_NAME,
        evidence=Evidence(
            request_raw=f"{param}={payload}",
            matched_at=_snippet(payload[: len(payload) // 5] or payload, body),
            notes=f"unencoded chars reflected: {''.join(sorted(survived))}",
        ),
    )


@register
class ReflectedXssScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "xss"
    min_aggressiveness = Aggressiveness.NORMAL

    async def _test_get(
        self, ctx: ScanContext, url: str, param: str
    ) -> Finding | None:
        marker = "hxss" + secrets.token_hex(3)
        payload = build_payload(marker)
        target = with_query_param(url, param, payload)
        try:
            resp = await ctx.http.get(target)
        except ScopeViolation:
            return None
        except httpx.HTTPError as exc:
            logger.debug("xss GET probe failed for %s: %s", target, exc)
            return None
        if not is_html_context(resp.headers.get("content-type")):
            return None
        reflected, survived = detect_reflection(marker, resp.text)
        if not reflected:
            return None
        return _make_finding(target, param, ParamLocation.QUERY, payload, resp.text, survived)

    async def _test_post(
        self, ctx: ScanContext, endpoint: Endpoint, param: str
    ) -> Finding | None:
        marker = "hxss" + secrets.token_hex(3)
        payload = build_payload(marker)
        data = {
            p.name: payload if p.name == param else (p.value or "1")
            for p in endpoint.params
            if p.location == ParamLocation.BODY
        }
        try:
            resp = await ctx.http.post(endpoint.url, data=data)
        except ScopeViolation:
            return None
        except httpx.HTTPError as exc:
            logger.debug("xss POST probe failed for %s: %s", endpoint.url, exc)
            return None
        if not is_html_context(resp.headers.get("content-type")):
            return None
        reflected, survived = detect_reflection(marker, resp.text)
        if not reflected:
            return None
        return _make_finding(endpoint.url, param, ParamLocation.BODY, payload, resp.text, survived)

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        tested: set[tuple[str, str, str]] = set()
        count = 0

        for endpoint in ctx.endpoints:
            if count >= MAX_TESTS:
                break
            path = urlsplit(endpoint.url).path

            if endpoint.method == HttpMethod.GET:
                names = {p.name for p in endpoint.params if p.location == ParamLocation.QUERY}
                for param in names:
                    key = ("GET", path, param)
                    if key in tested:
                        continue
                    tested.add(key)
                    count += 1
                    finding = await self._test_get(ctx, endpoint.url, param)
                    if finding is not None:
                        yield finding

            elif endpoint.method == HttpMethod.POST:
                names = {p.name for p in endpoint.params if p.location == ParamLocation.BODY}
                for param in names:
                    key = ("POST", path, param)
                    if key in tested:
                        continue
                    tested.add(key)
                    count += 1
                    finding = await self._test_post(ctx, endpoint, param)
                    if finding is not None:
                        yield finding


__all__ = [
    "ReflectedXssScanner",
    "detect_reflection",
    "is_html_context",
    "build_payload",
    "classify",
    "execution_payloads",
]
