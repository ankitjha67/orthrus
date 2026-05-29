"""IDOR / object enumeration scanner (PRD §6.7).

Without a second authenticated identity, true authorization-boundary testing is
limited, so this scanner detects the weaker but useful signal: numeric object
references where adjacent IDs return distinct valid objects (enumeration).
Findings are TENTATIVE and flagged for manual authorization review. Cross-user
boundary testing arrives once multi-session support lands.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.scanners._injection import InjectionPoint, injection_points, send, used_url
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register

SCANNER_NAME = "idor"
MAX_POINTS = 80
MIN_BODY = 50

_ID_HINTS = ("id", "uid", "user", "account", "order", "doc", "num", "pid", "key", "no")


def _is_id_param(name: str, value: str) -> bool:
    if not value.isdigit():
        return False
    lname = name.lower()
    return any(h in lname for h in _ID_HINTS) or value.isdigit()


def _similar_length(a: str, b: str, tolerance: float = 0.30) -> bool:
    la, lb = len(a), len(b)
    if max(la, lb) == 0:
        return False
    return abs(la - lb) / max(la, lb) <= tolerance


def idor_signal(original: str, neighbor: str, neighbor_status: int) -> bool:
    """Neighbor ID returns a distinct but structurally similar valid object."""
    if neighbor_status != 200:
        return False
    if len(neighbor) < MIN_BODY:
        return False
    return neighbor != original and _similar_length(original, neighbor)


def _param_value(point: InjectionPoint) -> str:
    for p in point.endpoint.params:
        if p.name == point.param:
            return p.value or ""
    return ""


@register
class IdorScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "idor"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        count = 0
        for point in injection_points(ctx):
            if count >= MAX_POINTS:
                break
            value = _param_value(point)
            if not _is_id_param(point.param, value):
                continue
            count += 1

            original = await send(ctx, point, value)
            if original is None or len(original.text) < MIN_BODY:
                continue

            number = int(value)
            for neighbor_value in (str(number + 1), str(number - 1) if number > 0 else None):
                if neighbor_value is None:
                    continue
                neighbor = await send(ctx, point, neighbor_value)
                if neighbor is None:
                    continue
                if idor_signal(original.text, neighbor.text, neighbor.status_code):
                    yield Finding(
                        vuln_type="idor",
                        title=f"Possible IDOR / object enumeration via '{point.param}'",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.TENTATIVE,
                        url=used_url(point, neighbor_value),
                        parameter=point.param,
                        param_location=point.location,
                        description=(
                            f"Changing the numeric reference '{point.param}' from {value} to "
                            f"{neighbor_value} returned a different valid object. If access control "
                            "is not enforced per object, this exposes other users' data. Manual "
                            "authorization review required."
                        ),
                        remediation=(
                            "Enforce per-object authorization on every request; prefer "
                            "unpredictable identifiers (UUIDv4) and scope queries to the session "
                            "owner."
                        ),
                        cwe="CWE-639",
                        scanner=SCANNER_NAME,
                        evidence=Evidence(
                            request_raw=f"{point.param}={neighbor_value}",
                            notes=f"id {value} -> {neighbor_value} returned a distinct 200 object",
                        ),
                    )
                    break


__all__ = ["IdorScanner", "idor_signal"]
