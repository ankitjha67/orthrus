"""Multi-identity authorization matrix - BOLA / BFLA (Autorize-style).

The single highest-leverage gap in automated DAST: most real-world bugs live
behind authentication, and broken *authorization* (one user reaching another
user's object, or a low-privilege user reaching a privileged function) is the
top OWASP risk (A01) and OWASP API #1/#5.

Given an operator-supplied list of identities (``--identities``), this scanner
treats the FIRST identity as the privileged **baseline** and replays each
discovered read endpoint as every OTHER identity, comparing responses:

* the baseline can access the resource (2xx), AND
* another identity gets the *same* successful response (same status + a body
  of near-identical size, with no access-denied marker)

→ that other identity reached a resource it should not have. Object-referencing
endpoints are reported as **BOLA** (CWE-639); the rest as **BFLA** (CWE-285).

Safety: only GET/HEAD endpoints are replayed (read-only, non-destructive); each
identity is sent through its own client with no shared cookie jar, so sessions
never cross-contaminate; every URL is scope-checked before any request.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.identity import Identity, identity_headers, parse_identities
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, HttpMethod, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation
from orthrus.utils.sensitivity import SensitiveHit, describe, has_high_value, scan_sensitive

logger = get_logger("scanner.authz-matrix")

SCANNER_NAME = "authz-matrix"
MAX_ENDPOINTS = 40
_UA = "Mozilla/5.0 (compatible; ORTHRUS authz-matrix)"

_DENY_MARKERS = (
    "access denied",
    "forbidden",
    "not authorized",
    "unauthorized",
    "permission denied",
    "login required",
    "please log in",
    "please sign in",
    "must be logged in",
)
_ID_PARAM_HINTS = ("id", "uid", "user", "account", "order", "doc", "pid", "key", "uuid", "guid")
_OBJECT_PATH = re.compile(r"/\d+(?:/|$)|/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-")


def _similar(a: str, b: str, tol: float = 0.10) -> bool:
    la, lb = len(a), len(b)
    if max(la, lb) == 0:
        return True
    return abs(la - lb) / max(la, lb) <= tol


def authz_verdict(base_status: int, base_body: str, other_status: int, other_body: str) -> str:
    """Compare a baseline (privileged) response to another identity's response.

    Returns "bypass" (other identity wrongly got access), "enforced" (properly
    denied), or "ambiguous" (inconclusive - left for manual review).
    Callers pass only endpoints the baseline could access (base_status < 400).
    """
    if other_status in (401, 403):
        return "enforced"
    if other_status in (301, 302, 303, 307, 308):  # redirected - typically to a login page
        return "enforced"
    if other_status >= 500:
        return "ambiguous"
    low = (other_body or "").lower()
    if any(marker in low for marker in _DENY_MARKERS):
        return "enforced"
    if other_status == base_status and _similar(base_body, other_body):
        return "bypass"
    return "ambiguous"


def is_public(anon_status: int, anon_body: str, base_status: int, base_body: str) -> bool:
    """True if an anonymous (no-auth) request gets an equivalent successful response.

    A public template/marketing page returns the same body to everyone, so a
    cross-identity "match" there is not an authorization boundary at all. Ruling
    this out is what stops the scanner flagging public pages as BOLA.
    """
    if anon_status >= 400 or 300 <= anon_status < 400:
        return False
    if any(marker in (anon_body or "").lower() for marker in _DENY_MARKERS):
        return False
    return anon_status == base_status and _similar(base_body, anon_body)


def is_object_ref(url: str, params: object) -> bool:
    """True if the endpoint references a specific object (numeric/UUID id) → BOLA."""
    if _OBJECT_PATH.search(urlsplit(url).path):
        return True
    for param in params or []:
        name = getattr(param, "name", "") or ""
        if any(hint in name.lower() for hint in _ID_PARAM_HINTS):
            return True
    return False


@register
class AuthorizationMatrixScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "broken-authorization"
    min_aggressiveness = Aggressiveness.NORMAL

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        identities = parse_identities(getattr(ctx.config, "identities", None))
        if len(identities) < 2:
            # Need a privileged baseline plus at least one identity to compare.
            return
        baseline = identities[0]
        # Only authenticated principals act as the "attacker"; a supplied anonymous
        # identity is folded into the public-page control below.
        others = [ident for ident in identities[1:] if ident.is_authenticated]

        timeout = getattr(ctx.config, "timeout", 30.0)
        clients = {
            ident.name: httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=False)
            for ident in identities
        }
        anon = Identity("anonymous")
        anon_client = httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=False)
        seen: set[tuple[str, str]] = set()
        emitted: set[tuple[str, str]] = set()
        try:
            count = 0
            for endpoint in ctx.endpoints:
                if count >= MAX_ENDPOINTS:
                    break
                if endpoint.method not in (HttpMethod.GET, HttpMethod.HEAD):
                    continue  # read-only only: never replay state-changing methods
                url = endpoint.url
                method = endpoint.method.value
                key = (method, urlsplit(url).path)
                if key in seen or not ctx.scope.is_allowed(url):
                    continue
                seen.add(key)
                count += 1

                base_resp = await self._send(clients[baseline.name], method, url, baseline)
                if base_resp is None or base_resp.status_code >= 400:
                    continue  # baseline can't access it → nothing to compare

                hits = scan_sensitive(base_resp.text)

                # Public-page control: does an anonymous request get the same body?
                anon_resp = await self._send(anon_client, method, url, anon)
                public = anon_resp is not None and is_public(
                    anon_resp.status_code, anon_resp.text, base_resp.status_code, base_resp.text
                )
                if public:
                    # A public template is not an authz boundary - unless it hands
                    # sensitive data to an unauthenticated client, which is its own bug.
                    dedup = (urlsplit(url).path, "anonymous")
                    if has_high_value(hits) and dedup not in emitted:
                        emitted.add(dedup)
                        yield self._finding(endpoint, url, baseline, anon, hits, unauth=True)
                    continue

                for other in others:
                    resp = await self._send(clients[other.name], method, url, other)
                    if resp is None:
                        continue
                    if authz_verdict(
                        base_resp.status_code, base_resp.text, resp.status_code, resp.text
                    ) != "bypass":
                        continue
                    dedup = (urlsplit(url).path, other.name)
                    if dedup in emitted:
                        continue
                    emitted.add(dedup)
                    yield self._finding(endpoint, url, baseline, other, hits, unauth=False)
        finally:
            for client in clients.values():
                await client.aclose()
            await anon_client.aclose()

    async def _send(
        self, client: httpx.AsyncClient, method: str, url: str, identity: Identity
    ) -> httpx.Response | None:
        headers = {"User-Agent": _UA, **identity_headers(identity)}
        try:
            return await client.request(method, url, headers=headers)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("authz replay failed for %s as %s: %s", url, identity.name, exc)
            return None

    def _finding(
        self, endpoint: object, url: str, baseline: Identity, other: Identity,
        hits: list[SensitiveHit] | None = None, *, unauth: bool = False,
    ) -> Finding:
        hits = hits or []
        path = urlsplit(url).path
        bola = is_object_ref(url, getattr(endpoint, "params", []))
        kind = "object-level (BOLA)" if bola else "function-level (BFLA)"
        cwe = "CWE-639" if bola else "CWE-285"
        # A leak of high-value data (PII / payment / tokens) is CRITICAL; a bare
        # authorization bypass with no sensitive body observed is HIGH.
        sensitive = has_high_value(hits)
        severity = Severity.CRITICAL if sensitive else Severity.HIGH
        data_note = f" Accessible data included: {describe(hits)}." if hits else ""
        if unauth:
            cwe = "CWE-306"  # missing authentication for a critical function
            title = f"Sensitive data reachable without authentication at {path}"
            description = (
                f"The resource returned an equivalent successful response to an anonymous "
                f"(no-credential) request as to the authenticated baseline '{baseline.name}'. An "
                f"unauthenticated attacker can read it directly.{data_note}"
            )
            match = f"anonymous == {baseline.name}"
            notes = (
                f"anonymous request received the same successful response as the authenticated "
                f"baseline '{baseline.name}'"
            )
        else:
            title = (
                f"Broken {kind} authorization: '{other.name}' reached '{baseline.name}'s resource"
            )
            description = (
                f"The resource was accessible to the privileged baseline identity "
                f"'{baseline.name}' and returned an equivalent successful response to identity "
                f"'{other.name}', which should not have access; an anonymous request was denied, so "
                f"the endpoint enforces authentication but not per-"
                f"{'object' if bola else 'function'} authorization - a client can reach another "
                f"principal's {'data' if bola else 'functionality'} by replaying the request with "
                f"their own session.{data_note}"
            )
            match = f"{other.name} == {baseline.name}"
            notes = (
                f"identity '{other.name}' received the same successful response as the privileged "
                f"baseline '{baseline.name}'"
            )
        if hits:
            notes += f"; sensitive data exposed: {describe(hits)}"
        return Finding(
            vuln_type="broken-authorization",
            title=title,
            severity=severity,
            confidence=Confidence.FIRM,
            url=url,
            description=description,
            remediation=(
                "Enforce authorization on every request server-side: check that the authenticated "
                "principal owns or is permitted the specific object/function (not just that they "
                "are logged in). Prefer unguessable identifiers and scope every query to the "
                "session owner; deny by default."
            ),
            cwe=cwe,
            scanner=SCANNER_NAME,
            evidence=Evidence(
                request_raw=f"{endpoint.method.value} {path}  (replayed as {other.name})",
                matched_at=match,
                notes=notes,
            ),
        )


__all__ = [
    "AuthorizationMatrixScanner",
    "authz_verdict",
    "is_object_ref",
]
