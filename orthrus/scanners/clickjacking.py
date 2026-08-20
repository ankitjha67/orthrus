"""Clickjacking / UI-redress scanner (framing-protection analysis).

A page is clickjackable when a cross-origin attacker can load it in an
``<iframe>`` and overlay it: the browser only refuses if the response carries
effective framing protection - a ``Content-Security-Policy: frame-ancestors``
directive that excludes arbitrary origins, or (legacy) ``X-Frame-Options:
DENY``/``SAMEORIGIN``. ``frame-ancestors`` takes precedence over XFO in modern
browsers; ``X-Frame-Options: ALLOW-FROM`` is deprecated and ignored, so it does
NOT protect.

Low-false-positive stance: only *sensitive, state-changing* pages (login, admin,
account, settings, payment, 2FA …) are reported - a framed marketing page is not
a real finding. The finding notes the SameSite caveat: if the session cookie is
``SameSite=Lax/Strict`` it is not sent on the cross-site framed request, so the
attack only lands where the authenticated state actually carries into the frame.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable, Mapping
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, HttpMethod, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.clickjacking")

SCANNER_NAME = "clickjacking"
MAX_TARGETS = 30
MAX_ORIGINS = 2

# Path fragments that mark a page as sensitive / state-changing - the only pages
# worth reporting as clickjackable.
_SENSITIVE_HINTS = (
    "login", "signin", "sign-in", "logon", "admin", "account", "settings",
    "profile", "password", "passwd", "email", "billing", "payment", "pay",
    "checkout", "cart", "transfer", "withdraw", "delete", "security", "2fa",
    "mfa", "otp", "oauth", "authorize", "authorise", "consent", "apikey",
    "api-key", "token", "connect", "unsubscribe", "invite", "member",
)

# Common sensitive paths to probe on each origin even if the crawler missed them.
_PROBE_PATHS = (
    "/login", "/signin", "/admin", "/account", "/settings", "/profile",
    "/account/settings", "/user/settings", "/password/change", "/oauth/authorize",
)


def frame_ancestors(csp: str) -> str | None:
    """Return the ``frame-ancestors`` directive value (lowercased) or None."""
    for directive in (csp or "").split(";"):
        directive = directive.strip().lower()
        if directive.startswith("frame-ancestors"):
            return directive[len("frame-ancestors"):].strip()
    return None


def is_frameable(headers: Mapping[str, str]) -> bool:
    """True if an arbitrary cross-origin page can frame this response.

    ``frame-ancestors`` wins when present: an explicit source list (``'none'``,
    ``'self'``, or specific hosts) blocks arbitrary framing; only a wildcard
    ``*`` / scheme-only source leaves it open. Otherwise fall back to
    ``X-Frame-Options`` (DENY/SAMEORIGIN protect; anything else - including the
    ignored ALLOW-FROM - does not).
    """
    lower = {k.lower(): (v or "") for k, v in headers.items()}
    fa = frame_ancestors(lower.get("content-security-policy", ""))
    if fa is not None:
        if not fa:  # empty directive == blocks all framing
            return False
        tokens = fa.split()
        # Blocked unless every source is a scheme-wide wildcard.
        broad = {"*", "http:", "https:", "http://*", "https://*"}
        return all(tok in broad for tok in tokens) and "'none'" not in tokens
    xfo = lower.get("x-frame-options", "").strip().lower()
    return xfo not in ("deny", "sameorigin")


def is_sensitive_path(path: str) -> bool:
    low = path.lower()
    return any(hint in low for hint in _SENSITIVE_HINTS)


def _origins(target: str, endpoint_urls: Iterable[str]) -> list[str]:
    seen: list[str] = []
    for url in (target, *endpoint_urls):
        parts = urlsplit(url)
        if parts.scheme and parts.netloc:
            origin = f"{parts.scheme}://{parts.netloc}"
            if origin not in seen:
                seen.append(origin)
    return seen


@register
class ClickjackingScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "clickjacking"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen: set[tuple[str, str]] = set()
        tested = 0

        # 1) Sensitive discovered HTML pages.
        candidates: list[str] = [
            ep.url for ep in ctx.endpoints
            if ep.method == HttpMethod.GET and is_sensitive_path(urlsplit(ep.url).path)
        ]
        # 2) A curated sensitive-path probe on each origin.
        for origin in _origins(ctx.config.target, [ep.url for ep in ctx.endpoints])[:MAX_ORIGINS]:
            candidates.extend(origin + p for p in _PROBE_PATHS)

        for url in candidates:
            if tested >= MAX_TARGETS:
                break
            parts = urlsplit(url)
            key = (parts.netloc, parts.path)
            if key in seen or not ctx.scope.is_allowed(url):
                continue
            seen.add(key)

            resp = await self._get(ctx, url)
            if resp is None or resp.status_code >= 400:
                continue
            if "html" not in resp.headers.get("content-type", "").lower():
                continue
            tested += 1
            if is_frameable(resp.headers):
                yield self._finding(url, dict(resp.headers))

    async def _get(self, ctx: ScanContext, url: str) -> httpx.Response | None:
        try:
            return await ctx.http.get(url, follow_redirects=False)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("clickjacking probe failed for %s: %s", url, exc)
            return None

    def _finding(self, url: str, headers: dict[str, str]) -> Finding:
        xfo = headers.get("x-frame-options") or headers.get("X-Frame-Options") or "(absent)"
        csp = headers.get("content-security-policy") or headers.get("Content-Security-Policy")
        fa = frame_ancestors(csp or "")
        detail = f"X-Frame-Options: {xfo}; frame-ancestors: {fa if fa is not None else '(absent)'}"
        return Finding(
            vuln_type="clickjacking",
            title=f"Clickjacking: sensitive page is framable ({urlsplit(url).path})",
            severity=Severity.MEDIUM,
            confidence=Confidence.FIRM,
            url=url,
            description=(
                f"The sensitive page {url} can be embedded in a cross-origin iframe: it carries no "
                f"effective framing protection ({detail}). An attacker can overlay it under a "
                "decoy UI and trick a logged-in victim into clicking state-changing controls "
                "(UI redress / clickjacking). Note: this lands only where the session cookie is "
                "sent in the framed request - if it is SameSite=Lax/Strict the attack needs a "
                "top-level-navigation or a cookie without that attribute."
            ),
            remediation=(
                "Send 'Content-Security-Policy: frame-ancestors 'none'' (or 'self') on sensitive "
                "responses, and 'X-Frame-Options: DENY' for legacy browsers. Do not rely on the "
                "deprecated ALLOW-FROM. Set session cookies SameSite=Lax or Strict."
            ),
            cwe="CWE-1021",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                matched_at=detail,
                notes="no frame-ancestors and no DENY/SAMEORIGIN X-Frame-Options on a sensitive page",
            ),
        )


__all__ = [
    "ClickjackingScanner",
    "frame_ancestors",
    "is_frameable",
    "is_sensitive_path",
]
