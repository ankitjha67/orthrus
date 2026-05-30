"""Exposed-secret scanner: credentials/keys leaked in responses & inline JS.

Passive-leaning detector that scans the bodies of discovered HTML/JS/JSON
endpoints (plus the root page) for high-signal secret patterns — AWS access
keys, Google API/OAuth tokens, Slack tokens, Stripe live keys, GitHub tokens,
and PEM private-key blocks. Each pattern is specific enough that a match is a
near-certain leak, keeping false positives low (no generic "looks like a
password" heuristics).

Secrets are NEVER stored in full: every match is redacted to a short preview
(first 4 chars + ``***``) before it touches a Finding or the logs. Bodies are
re-fetched for in-scope endpoints (recon only retains response headers), bounded
by ``MAX_FETCH``/``MAX_BODIES`` and deduplicated per ``(label, preview)``.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import (
    Aggressiveness,
    Confidence,
    Evidence,
    Finding,
    Severity,
)
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.secret-exposure")

SCANNER_NAME = "secret-exposure"
VULN_TYPE = "exposed-secret"

MAX_BODIES = 40
MAX_FETCH = 40

# (label, compiled regex, severity). Patterns are intentionally narrow/specific
# so a hit is almost certainly a real credential, not an incidental string.
_SECRET_RULES: tuple[tuple[str, re.Pattern[str], Severity], ...] = (
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.HIGH),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), Severity.HIGH),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"), Severity.HIGH),
    ("Stripe live key", re.compile(r"sk_live_[0-9A-Za-z]{24,}"), Severity.CRITICAL),
    ("GitHub token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"), Severity.HIGH),
    ("Google OAuth token", re.compile(r"ya29\.[0-9A-Za-z_\-]{20,}"), Severity.HIGH),
    (
        "Private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        Severity.CRITICAL,
    ),
)

# Content types worth scanning; anything image/binary-ish is skipped.
_TEXTUAL_HINTS: tuple[str, ...] = (
    "text/html",
    "text/plain",
    "application/javascript",
    "text/javascript",
    "application/json",
    "application/xml",
    "text/xml",
    "application/x-javascript",
)


def _redact(match: str) -> str:
    """Redact a secret to a non-recoverable preview: first 4 chars + ``***``."""
    return match[:4] + "***"


def find_secrets(text: str) -> list[tuple[str, str, Severity]]:
    """Find leaked secrets in ``text``.

    Returns ``(label, redacted_preview, severity)`` tuples, deduplicated by
    ``(label, preview)``. The full secret is never returned.
    """
    out: list[tuple[str, str, Severity]] = []
    seen: set[tuple[str, str]] = set()
    for label, pattern, severity in _SECRET_RULES:
        for m in pattern.finditer(text):
            preview = _redact(m.group(0))
            key = (label, preview)
            if key in seen:
                continue
            seen.add(key)
            out.append((label, preview, severity))
    return out


def is_scannable_body(content_type: str | None) -> bool:
    """True if a body of this content type is worth scanning for secrets.

    ``None``/unknown content types are scanned (recon may not have captured the
    type); explicitly binary/image/font/media types are skipped.
    """
    if not content_type:
        return True
    ct = content_type.split(";", 1)[0].strip().lower()
    if not ct:
        return True
    if any(ct == hint or ct.startswith(hint) for hint in _TEXTUAL_HINTS):
        return True
    # Skip obvious binary families outright.
    if ct.startswith(("image/", "audio/", "video/", "font/")):
        return False
    if ct in {"application/octet-stream", "application/pdf", "application/zip"}:
        return False
    # Be permissive for other text/* and application/* (often JSON-ish APIs).
    return ct.startswith("text/") or ct.startswith("application/")


@register
class SecretScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = VULN_TYPE
    min_aggressiveness = Aggressiveness.PASSIVE

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        emitted: set[tuple[str, str]] = set()  # (label, preview) across the host
        fetched_urls: set[str] = set()
        bodies_scanned = 0
        fetches = 0

        for url, content_type in self._candidate_sources(ctx):
            if bodies_scanned >= MAX_BODIES or fetches >= MAX_FETCH:
                break
            if url in fetched_urls:
                continue
            if not is_scannable_body(content_type):
                continue
            if not ctx.scope.is_allowed(url):
                continue
            fetched_urls.add(url)

            fetches += 1
            resp = await self._get(ctx, url)
            if resp is None:
                continue
            bodies_scanned += 1

            for label, preview, severity in find_secrets(resp.text):
                key = (label, preview)
                if key in emitted:
                    continue
                emitted.add(key)
                yield self._finding(url, label, preview, severity)

    def _candidate_sources(self, ctx: ScanContext) -> list[tuple[str, str | None]]:
        """Ordered, de-duplicated ``(url, content_type)`` sources to scan."""
        ordered: list[tuple[str, str | None]] = []
        seen: set[str] = set()

        root = ctx.config.target
        if root:
            ordered.append((root, None))
            seen.add(root)

        for ep in ctx.endpoints:
            url = ep.url.split("#", 1)[0]
            if url in seen:
                continue
            seen.add(url)
            ordered.append((url, ep.content_type))
        return ordered

    async def _get(self, ctx: ScanContext, url: str) -> httpx.Response | None:
        try:
            return await ctx.http.get(url, follow_redirects=False)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("secret-exposure fetch failed for %s: %s", url, exc)
            return None

    def _finding(
        self, url: str, label: str, preview: str, severity: Severity
    ) -> Finding:
        host = urlsplit(url).netloc or url
        return Finding(
            vuln_type=VULN_TYPE,
            title=f"Exposed secret: {label}",
            severity=severity,
            confidence=Confidence.FIRM,
            url=url,
            description=(
                f"A {label} appears to be exposed in the response served at {url}. "
                "Secrets embedded in HTML, inline JavaScript, or JSON responses are "
                "trivially harvested by anyone who loads the page and can grant direct "
                "access to cloud accounts, third-party APIs, source repositories, or "
                "payment systems."
            ),
            remediation=(
                "Revoke and rotate the leaked credential immediately. Never embed secrets "
                "in client-delivered code or responses; move them server-side, inject via "
                "environment/secret managers, and add secret-scanning to CI to block "
                "future leaks."
            ),
            cwe="CWE-798",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                matched_at=preview,
                notes=f"{label} leaked at {host} (value redacted)",
            ),
        )


__all__ = [
    "SecretScanner",
    "find_secrets",
    "is_scannable_body",
]
