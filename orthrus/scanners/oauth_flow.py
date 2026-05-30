"""OAuth 2.0 / OIDC authorization-flow misconfiguration scanner.

Identifies OAuth/OIDC *authorization* endpoints (``/authorize`` and friends, or
any endpoint carrying ``response_type`` + ``client_id`` + ``redirect_uri``) and
checks the flow for the classic, high-impact mistakes:

* **Missing ``state``** — no CSRF protection on the authorization request
  (authorization-code injection / login CSRF). CWE-352.
* **Authorization-code flow without PKCE** — ``response_type=code`` with no
  ``code_challenge``; public clients are open to code interception. CWE-287.
* **Implicit flow** — ``response_type=token``; the access token is exposed in the
  URL fragment (referrer/history/log leakage). CWE-522.
* **redirect_uri weak validation (active)** — replay the request with a tampered
  ``redirect_uri`` pointing at an attacker host; if the server 302-redirects
  there, authorization codes / tokens can be exfiltrated. CWE-601 (HIGH).

Static checks are passive; the single active probe is a read-only GET.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import parse_qs, urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.encoding import with_query_param
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.oauth-flow")

SCANNER_NAME = "oauth-flow"
MAX_ENDPOINTS = 20
_ATTACKER_HOST = "orthrus-oauth-evil.example"

_AUTHORIZE_PATHS = ("/authorize", "/oauth/authorize", "/oauth2/authorize", "/connect/authorize")


def is_oauth_authorize(url: str, param_names: set[str]) -> bool:
    """True if the endpoint looks like an OAuth/OIDC authorization request."""
    path = urlsplit(url).path.lower()
    if any(path.endswith(p) or path == p for p in _AUTHORIZE_PATHS) or "/authorize" in path:
        return True
    low = {p.lower() for p in param_names}
    return "response_type" in low and "client_id" in low and "redirect_uri" in low


def oauth_static_issues(params: dict[str, str]) -> list[tuple[Severity, str, str, str]]:
    """Return (severity, title, detail, cwe) for static OAuth-flow weaknesses."""
    issues: list[tuple[Severity, str, str, str]] = []
    low = {k.lower(): (v or "") for k, v in params.items()}
    response_type = low.get("response_type", "")

    if "state" not in low or not low.get("state"):
        issues.append((
            Severity.MEDIUM,
            "OAuth authorization request without 'state' (CSRF)",
            "No 'state' parameter is present, so the authorization response is not bound to the "
            "user's session — enabling login CSRF / authorization-code injection.",
            "CWE-352",
        ))
    if "token" in response_type:
        issues.append((
            Severity.MEDIUM,
            "OAuth implicit flow (response_type=token)",
            "The implicit flow returns the access token in the URL fragment, where it leaks via "
            "browser history, Referer headers, and logs. Use the authorization-code flow with PKCE.",
            "CWE-522",
        ))
    elif "code" in response_type and "code_challenge" not in low:
        issues.append((
            Severity.MEDIUM,
            "OAuth authorization-code flow without PKCE",
            "response_type=code without a 'code_challenge' (PKCE). Public clients are vulnerable to "
            "authorization-code interception.",
            "CWE-287",
        ))
    return issues


@register
class OAuthFlowScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "oauth-misconfig"

    def _authorize_endpoints(self, ctx: ScanContext) -> list[tuple[str, dict[str, str]]]:
        out: list[tuple[str, dict[str, str]]] = []
        seen: set[str] = set()
        for ep in ctx.endpoints:
            query = parse_qs(urlsplit(ep.url).query)
            params = {k: (v[0] if v else "") for k, v in query.items()}
            names = set(params) | {p.name for p in ep.params}
            path = urlsplit(ep.url).path
            if path in seen or not is_oauth_authorize(ep.url, names):
                continue
            seen.add(path)
            out.append((ep.url, params))
        return out[:MAX_ENDPOINTS]

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        for url, params in self._authorize_endpoints(ctx):
            if not ctx.scope.is_allowed(url):
                continue
            for severity, title, detail, cwe in oauth_static_issues(params):
                yield Finding(
                    vuln_type="oauth-misconfig",
                    title=title,
                    severity=severity,
                    confidence=Confidence.FIRM,
                    url=url,
                    description=detail,
                    remediation=(
                        "Use the authorization-code flow with PKCE, a per-request unguessable "
                        "'state' bound to the session, and exact (allow-list) redirect_uri matching."
                    ),
                    cwe=cwe,
                    scanner=SCANNER_NAME,
                    evidence=Evidence(matched_at=title, notes="OAuth authorization request analysis"),
                )

            if "redirect_uri" in {k.lower() for k in params}:
                finding = await self._redirect_uri_test(ctx, url, params)
                if finding is not None:
                    yield finding

    async def _redirect_uri_test(
        self, ctx: ScanContext, url: str, params: dict[str, str]
    ) -> Finding | None:
        original = next((v for k, v in params.items() if k.lower() == "redirect_uri"), "")
        evil = f"https://{_ATTACKER_HOST}/cb"
        target = with_query_param(url, "redirect_uri", evil)
        try:
            resp = await ctx.http.get(target, follow_redirects=False)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL):
            return None
        location = resp.headers.get("location", "") or ""
        if not resp.is_redirect or urlsplit(location).hostname != _ATTACKER_HOST:
            return None
        return Finding(
            vuln_type="oauth-misconfig",
            title="OAuth redirect_uri accepts an attacker-controlled host",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            url=url,
            description=(
                f"Replacing redirect_uri ({original!r}) with an attacker host caused the "
                f"authorization server to redirect to {location}. An attacker can register their "
                "host as the redirect target and steal authorization codes or access tokens "
                "(account takeover)."
            ),
            remediation=(
                "Validate redirect_uri against an exact, pre-registered allow-list (full string "
                "match, no wildcards/substrings); reject any mismatch."
            ),
            cwe="CWE-601",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                request_raw=f"redirect_uri={evil}",
                matched_at=location,
                notes="authorization server redirected to the attacker host",
            ),
        )


__all__ = ["OAuthFlowScanner", "is_oauth_authorize", "oauth_static_issues"]
