"""Privilege-escalation forced-browse across the identity lattice (BFLA).

The authorization-matrix scanner tests *discovered* endpoints. This scanner
covers the complementary gap: **unlinked** privileged routes (admin panels,
management APIs, debug consoles) that the crawler never reached but a
lower-privilege user can still hit directly - classic broken function-level
authorization (OWASP A01 / API #5).

Driven by the same `--identities` lattice (first = privileged baseline): it
forced-browses a curated corpus of administrative paths, keeps only the routes
the **baseline** can actually reach (so it never reports a 404/placeholder), and
flags any route a **lower-privilege or anonymous** identity reaches with an
equivalent successful response. Read-only GETs; each identity uses an isolated,
jar-less client; every URL is scope-checked; a per-origin soft-404 baseline
suppresses catch-all pages.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.identity import Identity, identity_headers, parse_identities
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from orthrus.scanners.authz_matrix import authz_verdict
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.privilege-escalation")

SCANNER_NAME = "privilege-escalation"
MAX_ORIGINS = 2
_UA = "Mozilla/5.0 (compatible; ORTHRUS privesc)"

# Clearly-administrative / privileged routes (kept deliberately unambiguous to
# minimise false positives - public-ish paths like /users or /metrics are out).
PRIVILEGED_PATHS: tuple[str, ...] = (
    "/admin",
    "/admin/",
    "/admin/users",
    "/admin/config",
    "/admin/settings",
    "/admin/dashboard",
    "/administrator",
    "/api/admin",
    "/api/admin/users",
    "/api/admin/config",
    "/api/v1/admin",
    "/api/internal",
    "/internal",
    "/manage",
    "/management",
    "/console",
    "/superadmin",
    "/staff",
    "/api/admin/keys",
    "/admin/api/users",
)


def _origins(ctx: ScanContext) -> list[str]:
    seen: list[str] = []
    for candidate in (ctx.config.target, *[ep.url for ep in ctx.endpoints]):
        parts = urlsplit(candidate)
        if parts.scheme and parts.netloc:
            origin = f"{parts.scheme}://{parts.netloc}"
            if origin not in seen:
                seen.append(origin)
    return seen[:MAX_ORIGINS]


def _is_real_route(resp: httpx.Response, soft404: httpx.Response | None) -> bool:
    """The baseline reached a genuine privileged route (2xx, not the soft-404)."""
    if resp.status_code >= 400:
        return False
    if soft404 is not None and soft404.status_code < 400:
        # Server returns 200 for everything (catch-all) -> can't distinguish.
        if abs(len(resp.text) - len(soft404.text)) <= max(1, len(soft404.text) // 20):
            return False
    return True


@register
class PrivilegeEscalationScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "privilege-escalation"
    min_aggressiveness = Aggressiveness.NORMAL

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        identities = parse_identities(getattr(ctx.config, "identities", None))
        if len(identities) < 2:
            return
        baseline, others = identities[0], identities[1:]
        timeout = getattr(ctx.config, "timeout", 30.0)
        clients = {
            ident.name: httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=False)
            for ident in identities
        }
        emitted: set[tuple[str, str]] = set()
        try:
            for origin in _origins(ctx):
                soft404 = await self._get(
                    clients[baseline.name], origin + f"/orthrus-privesc-{secrets.token_hex(4)}",
                    baseline,
                )
                for path in PRIVILEGED_PATHS:
                    url = origin + path
                    if not ctx.scope.is_allowed(url):
                        continue
                    base_resp = await self._get(clients[baseline.name], url, baseline)
                    if base_resp is None or not _is_real_route(base_resp, soft404):
                        continue
                    for other in others:
                        resp = await self._get(clients[other.name], url, other)
                        if resp is None:
                            continue
                        if authz_verdict(
                            base_resp.status_code, base_resp.text, resp.status_code, resp.text
                        ) != "bypass":
                            continue
                        key = (path, other.name)
                        if key in emitted:
                            continue
                        emitted.add(key)
                        yield self._finding(url, path, baseline, other)
        finally:
            for client in clients.values():
                await client.aclose()

    async def _get(
        self, client: httpx.AsyncClient, url: str, identity: Identity
    ) -> httpx.Response | None:
        headers = {"User-Agent": _UA, **identity_headers(identity)}
        try:
            return await client.get(url, headers=headers)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("privesc probe failed for %s as %s: %s", url, identity.name, exc)
            return None

    def _finding(self, url: str, path: str, baseline: Identity, other: Identity) -> Finding:
        confidence = Confidence.FIRM if other.is_authenticated else Confidence.TENTATIVE
        anon = (
            ""
            if other.is_authenticated
            else " (anonymous - confirm the route is meant to require authentication)"
        )
        return Finding(
            vuln_type="privilege-escalation",
            title=f"Privilege escalation: privileged route '{path}' reachable by '{other.name}'",
            severity=Severity.HIGH,
            confidence=confidence,
            url=url,
            description=(
                f"The administrative route '{path}' was reachable by the privileged baseline "
                f"identity '{baseline.name}' and returned an equivalent successful response to the "
                f"lower-privilege identity '{other.name}'{anon}. This unlinked privileged "
                "function lacks function-level authorization (BFLA): a low-privilege account can "
                "invoke administrative functionality by requesting the URL directly."
            ),
            remediation=(
                "Enforce role/permission checks on every privileged route server-side (deny by "
                "default), not just navigation hiding. Segregate admin functionality and verify the "
                "caller's authorization on each request."
            ),
            cwe="CWE-285",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                request_raw=f"GET {path}  (as {other.name})",
                matched_at=f"{other.name} reached {path}",
                notes=(
                    f"forced-browse: '{other.name}' reached an admin route also served to the "
                    f"privileged baseline '{baseline.name}'"
                ),
            ),
        )


__all__ = ["PrivilegeEscalationScanner", "PRIVILEGED_PATHS"]
