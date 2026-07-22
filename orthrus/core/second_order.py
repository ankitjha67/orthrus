"""Second-order / planted-payload registry.

A request-oriented scanner injects a payload and inspects the *same* response, so it
is blind to stored (second-order) bugs: a payload planted in a profile name or a
support ticket that detonates later, elsewhere - in a staff console, a report renderer,
or another user's page the scanner never visits.

This registry closes that gap non-destructively. It plants a canary into writable
fields that is BOTH an out-of-band beacon (loads the per-token callback URL when
rendered anywhere) AND a unique in-band marker (so if the stored value is reflected on
another page, that is caught too). Later it correlates each detonation - an OOB callback
or a marker seen on a different page - back to exactly where it was planted, turning a
"suspected but unconfirmable" blind bug into an evidenced finding.

The correlation is pure and testable; planting and harvesting go through the
scope-enforced client and the existing OOB collaborator (``ctx.callback``).
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import (
    Confidence,
    Evidence,
    Finding,
    HttpMethod,
    ParamLocation,
    Severity,
)
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("core.second-order")

MAX_PLANT_FORMS = 10


@dataclass
class PlantedPayload:
    """One canary planted into a writable field."""

    token: str
    marker: str
    sink_url: str
    sink_param: str
    payload: str
    callback_url: str = ""
    planted_at: str = ""


@dataclass
class SecondOrderHit:
    """A planted canary that detonated, with where it fired."""

    planted: PlantedPayload
    detonation: str  # "oob-callback" | "reflected-elsewhere"
    evidence: str


def build_payload(marker: str, callback_url: str) -> str:
    """A canary that beacons OOB when rendered AND carries the in-band marker.

    Rendered as HTML anywhere, the ``<img>`` loads the per-token callback URL (OOB
    proof); the marker in the ``alt`` survives text extraction so reflection on a
    different page is also detectable. Without a callback it degrades to a pure marker.
    """
    if callback_url:
        return f'"><img src="{callback_url}" alt="{marker}">'
    return f"{marker}<!--orthrus-so-->"


def correlate(
    planted: dict[str, PlantedPayload],
    interactions: dict[str, list],
    observations: list[tuple[str, str]],
) -> list[SecondOrderHit]:
    """Pure correlation: map OOB interactions and cross-page reflections to plants.

    ``interactions`` is ``{token: [interaction, ...]}`` from the collaborator;
    ``observations`` is ``[(observed_url, marker), ...]`` reflections seen on a page
    other than the plant site. De-duplicated so one plant yields at most one hit per
    detonation channel.
    """
    hits: list[SecondOrderHit] = []
    seen: set[tuple[str, str]] = set()

    for token, hit_list in interactions.items():
        plant = planted.get(token)
        if plant is None or not hit_list:
            continue
        key = (token, "oob")
        if key in seen:
            continue
        seen.add(key)
        first = hit_list[0]
        src = getattr(first, "source_ip", "") or "unknown"
        proto = getattr(first, "protocol", "http")
        hits.append(SecondOrderHit(plant, "oob-callback", f"{proto} callback from {src}"))

    marker_to_token = {p.marker: t for t, p in planted.items()}
    for observed_url, marker in observations:
        token = marker_to_token.get(marker)
        plant = planted.get(token) if token else None
        if plant is None or observed_url == plant.sink_url:
            continue
        key = (token or "", observed_url)
        if key in seen:
            continue
        seen.add(key)
        hits.append(SecondOrderHit(plant, "reflected-elsewhere", observed_url))

    return hits


class SecondOrderRegistry:
    """Plants canaries into writable fields and correlates later detonations."""

    def __init__(self, callback: object | None = None) -> None:
        self._callback = callback
        self._planted: dict[str, PlantedPayload] = {}
        self._observations: list[tuple[str, str]] = []

    @property
    def planted(self) -> list[PlantedPayload]:
        return list(self._planted.values())

    def plant(self, sink_url: str, sink_param: str) -> PlantedPayload:
        """Mint a canary for one field, register it, and return it (unsubmitted)."""
        if self._callback is not None:
            token, callback_url = self._callback.new_token()
        else:
            token, callback_url = secrets.token_hex(8), ""
        marker = f"ORTHRUSSO{token[:12]}"
        planted = PlantedPayload(
            token=token, marker=marker, sink_url=sink_url, sink_param=sink_param,
            payload=build_payload(marker, callback_url), callback_url=callback_url,
            planted_at=datetime.now(UTC).isoformat(),
        )
        self._planted[token] = planted
        return planted

    def observe(self, url: str, body: str) -> None:
        """Record any planted marker seen in ``body`` at a page other than its sink."""
        if not body:
            return
        for planted in self._planted.values():
            if planted.marker in body and url != planted.sink_url:
                entry = (url, planted.marker)
                if entry not in self._observations:
                    self._observations.append(entry)

    async def plant_writable_forms(self, ctx: ScanContext, *, max_forms: int = MAX_PLANT_FORMS) -> int:
        """Plant a canary into each discovered writable POST form. Returns the count."""
        forms = [
            ep for ep in ctx.endpoints
            if ep.method == HttpMethod.POST and getattr(ep, "source", "") == "form"
        ][:max_forms]
        count = 0
        for form in forms:
            body_params = [p.name for p in form.params if p.location == ParamLocation.BODY]
            if not body_params or not ctx.scope.is_allowed(form.url):
                continue
            planted = self.plant(form.url, body_params[0])
            data = {name: planted.payload for name in body_params}
            try:
                await ctx.http.post(form.url, data=data, follow_redirects=False)
                count += 1
            except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
                logger.debug("second-order plant failed for %s: %s", form.url, exc)
                del self._planted[planted.token]
        return count

    async def harvest(self, ctx: ScanContext) -> list[Finding]:
        """Poll the collaborator, re-observe sink pages, and emit second-order findings."""
        interactions: dict[str, list] = {}
        if self._callback is not None:
            for token in self._planted:
                try:
                    hits = await self._callback.poll(token)
                except Exception as exc:  # noqa: BLE001 - collaborator errors are non-fatal
                    logger.debug("callback poll failed for %s: %s", token, exc)
                    hits = []
                if hits:
                    interactions[token] = hits

        # Re-fetch each sink page + the target so a value reflected on another page is caught.
        pages = {p.sink_url for p in self._planted.values()} | {ctx.config.target}
        for url in pages:
            if not ctx.scope.is_allowed(url):
                continue
            try:
                resp = await ctx.http.get(url, follow_redirects=True)
                self.observe(url, resp.text)
            except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL):
                continue

        hits = correlate(self._planted, interactions, self._observations)
        return [self._finding(hit) for hit in hits]

    def _finding(self, hit: SecondOrderHit) -> Finding:
        plant = hit.planted
        sink = urlsplit(plant.sink_url).path or plant.sink_url
        if hit.detonation == "oob-callback":
            return Finding(
                vuln_type="second-order-injection",
                title=f"Second-order (stored) payload detonated out-of-band from {sink}",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                url=plant.sink_url,
                parameter=plant.sink_param,
                param_location=ParamLocation.BODY,
                description=(
                    f"A canary planted in '{plant.sink_param}' at {sink} later detonated out of "
                    f"band ({hit.evidence}). It executed somewhere the value is rendered that the "
                    "scanner never visited - a staff/admin console, a report renderer, or another "
                    "user's page. This is a confirmed stored/second-order injection (stored XSS or "
                    "SSRF, depending on the sink)."
                ),
                remediation=(
                    "Output-encode stored user content at every render site (including internal "
                    "consoles), validate on input, and apply a strict CSP. Treat stored data as "
                    "untrusted wherever it is later displayed."
                ),
                cwe="CWE-79",
                scanner="second-order",
                evidence=Evidence(
                    request_raw=f"planted in {plant.sink_param} at {plant.sink_url}",
                    matched_at=plant.token,
                    notes=f"out-of-band detonation: {hit.evidence}",
                ),
            )
        return Finding(
            vuln_type="second-order-injection",
            title=f"Stored value from {sink} reflected on another page",
            severity=Severity.MEDIUM,
            confidence=Confidence.FIRM,
            url=hit.evidence,
            parameter=plant.sink_param,
            param_location=ParamLocation.BODY,
            description=(
                f"A unique canary planted in '{plant.sink_param}' at {sink} was later reflected at "
                f"{hit.evidence}, proving the value is stored and rendered on a different page. "
                "Confirm whether it renders unencoded (stored XSS) or leaks data across contexts."
            ),
            remediation=(
                "Output-encode stored content on render and scope it to the owning context; do not "
                "reflect one user's stored input into another page or user's view unencoded."
            ),
            cwe="CWE-79",
            scanner="second-order",
            evidence=Evidence(
                request_raw=f"planted in {plant.sink_param} at {plant.sink_url}",
                matched_at=hit.evidence,
                notes=f"planted marker reflected at {hit.evidence}",
            ),
        )


__all__ = [
    "PlantedPayload",
    "SecondOrderHit",
    "SecondOrderRegistry",
    "build_payload",
    "correlate",
    "MAX_PLANT_FORMS",
]
