"""Response baseline / soft-404 calibration for false-positive suppression.

Path-probing scanners (content discovery, declarative templates) are easily
fooled by a target that returns a *success* page for every URL — a catch-all or
soft-404. Before scanning, ORTHRUS sends a handful of deliberately nonsensical
requests and records how the target answers them. A later response that looks
just like those baseline answers is almost certainly the catch-all rather than a
genuine hit, so scanners consult the profile and drop it.

Everything here is pure except :func:`build_baseline`, which issues the probe
requests through the scope-enforced HttpClient. The fingerprint compares
structure (status, length, word/line counts) rather than exact bytes so it still
recognises a catch-all that echoes the requested path back into the body.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import httpx

from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

if TYPE_CHECKING:
    from orthrus.core.context import ScanContext

logger = get_logger("baseline")

# Statuses that indicate "the resource exists / responded" rather than a clean
# 404. A catch-all answers nonsense paths with one of these.
FOUND_STATUSES = frozenset({200, 201, 202, 203, 204, 206, 301, 302, 307, 308, 401, 403})

DEFAULT_SAMPLES = 3


@dataclass(frozen=True)
class ResponseFingerprint:
    """A structural signature of a response, robust to small body variation."""

    status: int
    length: int
    word_count: int
    line_count: int

    @classmethod
    def from_response(cls, status: int, body: str) -> ResponseFingerprint:
        return cls(
            status=status,
            length=len(body),
            word_count=len(body.split()),
            line_count=body.count("\n") + 1,
        )

    def similar_to(
        self, other: ResponseFingerprint, *, length_tol: float = 0.05, count_tol: int = 2
    ) -> bool:
        """Whether two responses are structurally alike (same status, near size).

        Matches on byte length within tolerance OR on near-identical word and
        line counts — the latter catches catch-alls whose only variation is an
        echoed path/token, which barely shifts the counts.
        """
        if self.status != other.status:
            return False
        if abs(self.length - other.length) <= max(48, int(other.length * length_tol)):
            return True
        return (
            abs(self.word_count - other.word_count) <= count_tol
            and abs(self.line_count - other.line_count) <= count_tol
        )


@dataclass
class BaselineProfile:
    """Calibrated catch-all/soft-404 signatures gathered from nonsense probes."""

    fingerprints: list[ResponseFingerprint] = field(default_factory=list)

    @property
    def catch_all(self) -> bool:
        """True if nonsense paths returned a 'found'-ish status (a soft-404 site)."""
        return any(fp.status in FOUND_STATUSES for fp in self.fingerprints)

    def matches(self, status: int, body: str) -> bool:
        """Whether a response looks like the calibrated catch-all (i.e. not a real hit)."""
        if not self.fingerprints:
            return False
        fp = ResponseFingerprint.from_response(status, body)
        return any(fp.similar_to(base) for base in self.fingerprints)


def root_url(target: str) -> str:
    """Scheme://host[:port] for ``target`` (defaults to http when scheme-less)."""
    parts = urlsplit(target if "://" in target else f"//{target}")
    return f"{parts.scheme or 'http'}://{parts.netloc or parts.path}"


def _probe_paths(token: str) -> list[str]:
    """A few distinct nonsense paths (plain, nested, extensioned) to characterise
    catch-alls that key on depth or file extension."""
    return [
        f"orthrus-not-found-{token}",
        f"orthrus-not-found-{token}/{secrets.token_hex(3)}",
        f"orthrus-not-found-{token}.html",
    ]


async def build_baseline(ctx: ScanContext, *, samples: int = DEFAULT_SAMPLES) -> BaselineProfile:
    """Probe the target root with nonsense paths and record response signatures."""
    profile = BaselineProfile()
    root = root_url(ctx.config.target)
    token = secrets.token_hex(6)
    for path in _probe_paths(token)[:samples]:
        url = f"{root.rstrip('/')}/{path}"
        if not ctx.scope.is_allowed(url):
            continue
        try:
            resp = await ctx.http.get(url, follow_redirects=False)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL):
            continue
        profile.fingerprints.append(
            ResponseFingerprint.from_response(resp.status_code, resp.text)
        )
    if profile.catch_all:
        logger.info(
            "baseline: target returns a catch-all response for unknown paths; "
            "calibrating to suppress false positives"
        )
    return profile


__all__ = [
    "ResponseFingerprint",
    "BaselineProfile",
    "build_baseline",
    "root_url",
    "FOUND_STATUSES",
]
