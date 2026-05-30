"""Content-Security-Policy weakness analyzer (PRD §6.8 Security Headers).

Passive scanner: it inspects the CSP header already captured during recon (and
fetches the target root once if no header is available) and reports *weak* but
PRESENT directives — ``'unsafe-inline'``/``'unsafe-eval'`` script sources, bare
wildcards, ``data:`` script sources, missing ``object-src``/``frame-ancestors``,
and insecure ``http:`` sources.

This deliberately does NOT flag a MISSING CSP — the dedicated security-headers
scanner already covers that. ``analyze_csp`` returns ``[]`` for an absent policy
so the two scanners never duplicate each other. Findings are deduped per origin
since the policy is usually server-wide.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.csp")

SCANNER_NAME = "csp"
MAX_ORIGINS = 3
_SNIPPET_MAX = 120


def parse_csp(csp: str) -> dict[str, list[str]]:
    """Parse a CSP header into ``directive -> [sources]`` (all lower-cased)."""
    directives: dict[str, list[str]] = {}
    for raw in csp.split(";"):
        tokens = raw.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name in directives:
            continue  # first occurrence wins, per the CSP spec
        directives[name] = [t.lower() for t in tokens[1:]]
    return directives


def _script_sources(directives: dict[str, list[str]]) -> list[str]:
    """Effective script sources: script-src if present, else default-src."""
    if "script-src" in directives:
        return directives["script-src"]
    return directives.get("default-src", [])


def analyze_csp(csp: str | None) -> list[tuple[Severity, str, str]]:
    """Return ``(severity, title, detail)`` for each weakness in a PRESENT policy.

    Returns ``[]`` when ``csp`` is ``None``/empty — a missing CSP is reported by
    the security-headers scanner, not here.
    """
    if not csp or not csp.strip():
        return []

    directives = parse_csp(csp)
    script_src = _script_sources(directives)
    default_src = directives.get("default-src", [])
    findings: list[tuple[Severity, str, str]] = []

    if "'unsafe-inline'" in script_src:
        findings.append(
            (
                Severity.MEDIUM,
                "CSP allows 'unsafe-inline' scripts",
                "script-src (or fallback default-src) permits 'unsafe-inline', which "
                "neutralizes CSP's main XSS protection by allowing inline <script> and "
                "event-handler execution.",
            )
        )

    if "'unsafe-eval'" in script_src:
        findings.append(
            (
                Severity.MEDIUM,
                "CSP allows 'unsafe-eval' scripts",
                "script-src (or fallback default-src) permits 'unsafe-eval', allowing "
                "eval()/new Function()/setTimeout(string) and weakening XSS containment.",
            )
        )

    if "*" in script_src:
        findings.append(
            (
                Severity.MEDIUM,
                "CSP script source allows any origin (*)",
                "A bare wildcard '*' in the script source list lets scripts load from any "
                "origin, defeating the policy's restriction on script provenance.",
            )
        )

    # data: in script-src is dangerous (XSS via data: URIs); only check the
    # explicit script-src list, not the default-src fallback.
    if "data:" in directives.get("script-src", []):
        findings.append(
            (
                Severity.MEDIUM,
                "CSP allows data: scripts",
                "script-src permits the data: scheme, letting an attacker execute scripts "
                "from attacker-controlled data: URIs (a common CSP bypass).",
            )
        )

    if "object-src" not in directives and default_src != ["'none'"]:
        findings.append(
            (
                Severity.LOW,
                "CSP missing object-src 'none'",
                "No object-src directive is set and default-src is not 'none', so plugins "
                "(<object>/<embed>) can load — a legacy XSS/exfiltration vector.",
            )
        )

    if "frame-ancestors" not in directives:
        findings.append(
            (
                Severity.LOW,
                "CSP missing frame-ancestors (clickjacking)",
                "No frame-ancestors directive is set, so the page may be framed by any "
                "origin and is not protected against clickjacking via CSP.",
            )
        )

    for sources in directives.values():
        if any(src.startswith("http:") for src in sources):
            findings.append(
                (
                    Severity.LOW,
                    "CSP permits insecure http: sources",
                    "The policy allowlists one or more plaintext http: sources, which can be "
                    "tampered with by a network attacker and undermines the policy.",
                )
            )
            break

    return findings


def _origins_from(target: str, endpoint_urls: list[str]) -> list[str]:
    """Distinct ``scheme://host`` origins from the target + discovered endpoints."""
    seen: list[str] = []
    for url in (target, *endpoint_urls):
        parts = urlsplit(url)
        if parts.scheme and parts.netloc:
            origin = f"{parts.scheme}://{parts.netloc}"
            if origin not in seen:
                seen.append(origin)
    return seen


def _get_csp(headers: dict[str, str]) -> str | None:
    """Case-insensitive lookup of the Content-Security-Policy header."""
    for key, value in headers.items():
        if key.lower() == "content-security-policy":
            return value
    return None


@register
class CspAnalyzerScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "csp"
    min_aggressiveness = Aggressiveness.PASSIVE

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen: set[tuple[str, str]] = set()

        # Map each origin to a CSP header captured during recon (first wins).
        origin_csp: dict[str, str] = {}
        for ep in ctx.endpoints:
            if not ep.response_headers:
                continue
            parts = urlsplit(ep.url)
            if not (parts.scheme and parts.netloc):
                continue
            origin = f"{parts.scheme}://{parts.netloc}"
            if origin in origin_csp:
                continue
            csp = _get_csp(ep.response_headers)
            if csp:
                origin_csp[origin] = csp

        origins = _origins_from(ctx.config.target, [ep.url for ep in ctx.endpoints])
        origins = origins[:MAX_ORIGINS]

        for origin in origins:
            csp = origin_csp.get(origin)
            if csp is None:
                # No captured CSP for this origin — fetch the root once.
                if not ctx.scope.is_allowed(origin + "/"):
                    continue
                resp = await self._get(ctx, origin + "/")
                if resp is None:
                    continue
                csp = _get_csp(dict(resp.headers))
            if not csp:
                continue

            directives = parse_csp(csp)
            for severity, title, detail in analyze_csp(csp):
                key = (origin, title)
                if key in seen:
                    continue
                seen.add(key)
                yield self._finding(origin + "/", severity, title, detail, directives)

    async def _get(self, ctx: ScanContext, url: str) -> httpx.Response | None:
        try:
            return await ctx.http.get(url, follow_redirects=False)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("csp probe failed for %s: %s", url, exc)
            return None

    def _finding(
        self,
        url: str,
        severity: Severity,
        title: str,
        detail: str,
        directives: dict[str, list[str]],
    ) -> Finding:
        snippet = _directive_snippet(title, directives)
        return Finding(
            vuln_type="csp",
            title=title,
            severity=severity,
            confidence=Confidence.FIRM,
            url=url,
            description=detail,
            remediation=(
                "Tighten the Content-Security-Policy: remove 'unsafe-inline'/'unsafe-eval' "
                "(use nonces or hashes), drop wildcard/data:/http: sources, set "
                "object-src 'none', and add frame-ancestors 'none' (or an explicit allowlist)."
            ),
            cwe="CWE-693",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                matched_at=snippet,
                notes="weak directive in present Content-Security-Policy",
            ),
        )


def _directive_snippet(title: str, directives: dict[str, list[str]]) -> str:
    """Best-effort snippet of the directive that triggered the finding."""
    name = "script-src" if "script-src" in directives else "default-src"
    if "object-src" in title:
        name = "object-src" if "object-src" in directives else "default-src"
    elif "frame-ancestors" in title:
        name = "frame-ancestors"
    elif "http:" in title:
        for dname, sources in directives.items():
            if any(src.startswith("http:") for src in sources):
                name = dname
                break
    sources = directives.get(name)
    if sources is None:
        text = name
    else:
        text = " ".join([name, *sources]).strip()
    if len(text) > _SNIPPET_MAX:
        text = text[:_SNIPPET_MAX] + "..."
    return text


__all__ = [
    "CspAnalyzerScanner",
    "analyze_csp",
    "parse_csp",
]
