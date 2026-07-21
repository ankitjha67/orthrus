"""Mass-assignment / object-property injection scanner (OWASP API #3).

APIs that bind a request body straight onto an internal object let a client set
fields the server should control - ``role``, ``is_admin``, ``verified``,
``account_balance`` - escalating privilege or tampering with state. This scanner
probes discovered write endpoints (POST/PUT/PATCH) by adding well-known
privileged field names, each carrying a unique random nonce, and flags the
endpoint when those nonces are reflected back in the response: proof the server
incorporated attacker-supplied fields it never advertised.

Detection only. The nonce makes the signal unforgeable (it cannot appear by
chance), but whether a bound field is actually *honored* downstream is a manual
follow-up, so findings are FIRM and call for authorization review. Adding fields
is non-destructive, so DELETE is intentionally excluded.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import (
    Confidence,
    Endpoint,
    Evidence,
    Finding,
    HttpMethod,
    ParamLocation,
    Severity,
)
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.mass-assignment")

SCANNER_NAME = "mass-assignment"
MAX_ENDPOINTS = 60

# Methods that create/update an object (so extra fields may be bound). DELETE is
# excluded: adding fields to it could destroy a resource.
WRITE_METHODS = (HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH)

# Privileged / server-controlled field names an attacker would try to set.
PRIVILEGED_FIELDS: tuple[str, ...] = (
    "role",
    "roles",
    "is_admin",
    "isAdmin",
    "admin",
    "is_superuser",
    "is_staff",
    "is_active",
    "active",
    "verified",
    "is_verified",
    "email_verified",
    "approved",
    "enabled",
    "account_balance",
    "balance",
    "credit",
    "group",
    "group_id",
    "grants",
    "permissions",
    "scopes",
    "user_id",
    "owner_id",
)

# Binding one of these is an authorization/privilege escalation -> HIGH severity.
_HIGH_RISK = frozenset(
    f.lower()
    for f in (
        "role",
        "roles",
        "is_admin",
        "isAdmin",
        "admin",
        "is_superuser",
        "is_staff",
        "grants",
        "permissions",
        "scopes",
        "group",
        "group_id",
    )
)


def _body_location(endpoint: Endpoint) -> ParamLocation | None:
    """Pick the body encoding to probe: JSON if any JSON param, else form body."""
    locations = {p.location for p in endpoint.params}
    if ParamLocation.JSON in locations:
        return ParamLocation.JSON
    if ParamLocation.BODY in locations:
        return ParamLocation.BODY
    return None


def _base_body(endpoint: Endpoint, location: ParamLocation) -> dict[str, str]:
    """The endpoint's known fields with their sample values (the legitimate body)."""
    return {p.name: (p.value or "1") for p in endpoint.params if p.location == location}


def detect_bound_fields(
    probes: dict[str, str], baseline_body: str, injected_body: str
) -> list[str]:
    """Return the privileged fields whose nonce appears only after injection."""
    return [
        field
        for field, nonce in probes.items()
        if nonce in injected_body and nonce not in baseline_body
    ]


def _severity(bound: list[str]) -> Severity:
    return Severity.HIGH if any(f.lower() in _HIGH_RISK for f in bound) else Severity.MEDIUM


@register
class MassAssignmentScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "mass-assignment"

    async def _send_body(
        self, ctx: ScanContext, endpoint: Endpoint, location: ParamLocation, body: dict[str, str]
    ) -> httpx.Response | None:
        method = endpoint.method.value
        try:
            if location == ParamLocation.JSON:
                return await ctx.http.request(method, endpoint.url, json=body)
            return await ctx.http.request(method, endpoint.url, data=body)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("mass-assignment probe failed for %s: %s", endpoint.url, exc)
            return None

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen: set[tuple[str, str]] = set()
        count = 0
        for endpoint in ctx.endpoints:
            if count >= MAX_ENDPOINTS:
                break
            if endpoint.method not in WRITE_METHODS:
                continue
            location = _body_location(endpoint)
            if location is None:
                continue
            key = (endpoint.method.value, urlsplit(endpoint.url).path)
            if key in seen:
                continue
            seen.add(key)
            count += 1

            finding = await self._probe(ctx, endpoint, location)
            if finding is not None:
                yield finding

    async def _probe(
        self, ctx: ScanContext, endpoint: Endpoint, location: ParamLocation
    ) -> Finding | None:
        base = _base_body(endpoint, location)
        baseline = await self._send_body(ctx, endpoint, location, base)
        if baseline is None:
            return None

        nonce = secrets.token_hex(4)
        # Per-field nonce so a reflection tells us exactly which field was bound.
        probes = {field: f"orthrus{nonce}{i}" for i, field in enumerate(PRIVILEGED_FIELDS)}
        injected = {**base, **probes}
        resp = await self._send_body(ctx, endpoint, location, injected)
        if resp is None:
            return None

        bound = detect_bound_fields(probes, baseline.text, resp.text)
        if not bound:
            return None

        shown = ", ".join(sorted(bound))
        return Finding(
            vuln_type="mass-assignment",
            title=f"Mass assignment: server bound unexpected field(s) on {endpoint.method.value} request",
            severity=_severity(bound),
            confidence=Confidence.FIRM,
            url=endpoint.url,
            param_location=location,
            description=(
                f"The endpoint incorporated attacker-supplied privileged field(s) [{shown}] into "
                "its response object even though they were not part of the documented request. "
                "This indicates the request body is bound directly to an internal model "
                "(mass assignment / autobinding), allowing a client to set server-controlled "
                "properties. Confirm whether the bound values are persisted/honored downstream."
            ),
            remediation=(
                "Bind requests to an explicit allow-list of writable fields (a DTO / serializer "
                "with read-only fields marked), never the raw model. Reject or ignore unknown "
                "fields and enforce authorization on privileged attributes server-side."
            ),
            cwe="CWE-915",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                request_raw=f"injected fields: {shown}",
                notes=f"unique nonce for each injected field was reflected in the response ({shown})",
            ),
        )


__all__ = ["MassAssignmentScanner", "detect_bound_fields", "PRIVILEGED_FIELDS"]
