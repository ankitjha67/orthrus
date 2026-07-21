"""Shadow / improper-inventory API scanner (OWASP API9:2023).

APIs accrete *undocumented* surface over their lifetime: an old ``/v1`` left
running after ``/v2`` shipped, an ``/internal`` or ``/beta`` namespace never
meant for the public, a forgotten ``/admin`` or ``/test`` variant. These shadow
endpoints frequently lack the hardening of the current version (weaker authz,
older bugs, more verbose responses) and are a classic improper-inventory finding.

The probe is read-only. For each discovered endpoint whose path carries a
version-ish segment (``/v\\d+/``, ``/api/v\\d+/``, ``/internal/``, ``/beta/``),
this scanner swaps that segment for each sibling variant (v1, v2, v3, internal,
beta, admin, test, old) and GETs it. To avoid false positives on catch-all
hosts, it first calibrates a soft-404 by requesting a random nonexistent sibling
path on the same origin; a variant only counts as *reachable* when it answers
200/401/403 and is distinct from that soft-404 baseline.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import AsyncIterator
from urllib.parse import urlsplit, urlunsplit

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

logger = get_logger("scanner.shadow-api")

SCANNER_NAME = "shadow-api"
MAX_BASES = 15
MAX_PROBES = 120

# Variants we substitute for a discovered version-ish segment.
_VARIANTS: tuple[str, ...] = ("v1", "v2", "v3", "internal", "beta", "admin", "test", "old")

# A path segment is "version-ish" if it is vN, internal, or beta.
_SEGMENT_RE = re.compile(r"^(?:v\d+|internal|beta)$", re.IGNORECASE)


def _version_segment_index(segments: list[str]) -> int | None:
    """Index of the first version-ish segment in a split path, else None."""
    for i, seg in enumerate(segments):
        if _SEGMENT_RE.match(seg):
            return i
    return None


def version_variants(url: str) -> list[str]:
    """Sibling-variant URLs produced by swapping a version-ish path segment.

    Given a URL whose path contains ``/v\\d+/``, ``/api/v\\d+/``, ``/internal/``
    or ``/beta/``, return one URL per variant in :data:`_VARIANTS` (excluding the
    original segment value). Returns ``[]`` when no version segment is present.
    """
    parts = urlsplit(url)
    if not parts.netloc:
        return []
    raw_segments = parts.path.split("/")
    # Work on a copy with leading-empty (from the root "/") preserved by index.
    idx = _version_segment_index(raw_segments)
    if idx is None:
        return []
    original = raw_segments[idx].lower()
    out: list[str] = []
    seen: set[str] = set()
    for variant in _VARIANTS:
        if variant.lower() == original:
            continue
        new_segments = list(raw_segments)
        new_segments[idx] = variant
        new_path = "/".join(new_segments)
        variant_url = urlunsplit((parts.scheme, parts.netloc, new_path, "", ""))
        if variant_url not in seen:
            seen.add(variant_url)
            out.append(variant_url)
    return out


def reachable_variant(
    status: int, body: str, base404_status: int, base404_body: str
) -> bool:
    """True if a probed variant looks like a real, distinct endpoint.

    Reachable means it answered 200/401/403 and is NOT identical to the
    calibrated soft-404 (same status *and* body), which would just be a
    catch-all response.
    """
    if status not in (200, 401, 403):
        return False
    if status == base404_status and body.strip() == base404_body.strip():
        return False
    return True


@register
class ShadowApiScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "shadow-api"
    min_aggressiveness = Aggressiveness.NORMAL

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        bases = self._candidate_bases(ctx)
        probes = 0
        emitted: set[str] = set()
        # Per-origin soft-404 calibration cache: origin -> (status, body).
        soft404: dict[str, tuple[int, str] | None] = {}

        for base_url in bases:
            variants = version_variants(base_url)
            if not variants:
                continue
            origin = self._origin(base_url)
            baseline = await self._soft404(ctx, base_url, origin, soft404)
            if baseline is None:
                continue
            base_status, base_body = baseline

            for variant in variants:
                if probes >= MAX_PROBES:
                    return
                # Skip variants that merely reproduce a path we already flagged.
                if self._dedup_key(variant) in emitted:
                    continue
                if not ctx.scope.is_allowed(variant):
                    continue
                probes += 1
                resp = await self._get(ctx, variant)
                if resp is None:
                    continue
                if not reachable_variant(
                    resp.status_code, resp.text, base_status, base_body
                ):
                    continue
                emitted.add(self._dedup_key(variant))
                yield self._finding(variant, resp.status_code)

    # ----------------------------------------------------------------- helpers
    def _candidate_bases(self, ctx: ScanContext) -> list[str]:
        """Discovered URLs whose path has a version segment (dedup, capped)."""
        bases: list[str] = []
        seen: set[str] = set()
        for ep in ctx.endpoints:
            parts = urlsplit(ep.url)
            if not parts.netloc:
                continue
            if _version_segment_index(parts.path.split("/")) is None:
                continue
            key = self._dedup_key(ep.url)
            if key in seen:
                continue
            seen.add(key)
            bases.append(ep.url)
            if len(bases) >= MAX_BASES:
                break
        return bases

    async def _soft404(
        self,
        ctx: ScanContext,
        base_url: str,
        origin: str,
        cache: dict[str, tuple[int, str] | None],
    ) -> tuple[int, str] | None:
        """Calibrate a soft-404 baseline for the origin (cached per origin)."""
        if origin not in cache:
            parts = urlsplit(base_url)
            bogus_path = f"/orthrus-shadow-{secrets.token_hex(4)}/probe"
            bogus = urlunsplit((parts.scheme, parts.netloc, bogus_path, "", ""))
            if not ctx.scope.is_allowed(bogus):
                cache[origin] = None
            else:
                resp = await self._get(ctx, bogus)
                cache[origin] = (
                    (resp.status_code, resp.text) if resp is not None else None
                )
        return cache[origin]

    @staticmethod
    def _origin(url: str) -> str:
        parts = urlsplit(url)
        return f"{parts.scheme}://{parts.netloc}"

    @staticmethod
    def _dedup_key(url: str) -> str:
        parts = urlsplit(url)
        return f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"

    async def _get(self, ctx: ScanContext, url: str) -> httpx.Response | None:
        try:
            return await ctx.http.get(url, follow_redirects=False)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("shadow-api probe failed for %s: %s", url, exc)
            return None

    def _finding(self, variant: str, status: int) -> Finding:
        gated = status in (401, 403)
        return Finding(
            vuln_type="shadow-api",
            title=f"Undocumented API surface reachable: {variant}",
            severity=Severity.LOW if gated else Severity.MEDIUM,
            confidence=Confidence.FIRM,
            url=variant,
            description=(
                f"A version/namespace variant of a documented endpoint answered with HTTP "
                f"{status}, indicating undocumented 'shadow' API surface is still reachable. "
                "Older versions (e.g. /v1 when the product targets /v2) and internal/beta/admin "
                "namespaces commonly miss the hardening of the current API - weaker authorization, "
                "unpatched bugs, and more verbose responses - and are an improper-inventory risk "
                "(OWASP API9). "
                + (
                    "It returned an auth-required status, so it exists but is access-controlled."
                    if gated
                    else "It returned a successful response, suggesting it is openly accessible."
                )
            ),
            remediation=(
                "Maintain an authoritative inventory of every deployed API version and namespace. "
                "Decommission retired versions and non-production (internal/beta/test) surfaces, or "
                "place them behind network controls and authentication. Ensure all reachable "
                "versions share the same security controls (authz, rate limits, validation)."
            ),
            cwe="CWE-668",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                matched_at=f"HTTP {status}",
                request_raw=f"GET {urlsplit(variant).path}",
                notes="version/namespace variant distinct from soft-404 baseline",
            ),
        )


__all__ = ["ShadowApiScanner", "version_variants", "reachable_variant"]
