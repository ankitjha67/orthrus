"""Intruder - a scope-enforced request fuzzer (Burp-Intruder / Caido-Automate parity).

Mark injection positions in a raw HTTP request with ``§`` pairs, supply one or more
payload lists, and ORTHRUS generates the request set per attack mode, sends each
through the scope-enforced replay path, and ranks the responses so the odd one out
(a different status or length) stands out.

Attack modes (Burp's four):
- **sniper**      one position at a time, one payload list; others keep their base value.
- **batteringram** the same payload in every position at once.
- **pitchfork**   one payload list per position, advanced in lockstep.
- **clusterbomb** every combination of the per-position payload lists (cartesian).

Scope enforcement is load-bearing: every generated request is validated against the
authorized scope before it is sent, exactly like a scan or a replay.
"""

from __future__ import annotations

import asyncio
import itertools
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import quote

from orthrus.proxy.replay import ReplayResult, RequestSpec, parse_raw_http, replay

if TYPE_CHECKING:
    from orthrus.utils.scope import ScopeValidator

MARKER = "§"
ATTACK_MODES = ("sniper", "batteringram", "pitchfork", "clusterbomb")
DEFAULT_MAX_REQUESTS = 5000


def extract_positions(raw: str) -> tuple[list[str], list[str]]:
    """Split a `§`-marked request into (literals[n+1], base_values[n]).

    ``GET /a?id=§1§&q=§x§`` -> literals ``['GET /a?id=', '&q=', '']``, bases ``['1','x']``.
    Raises if the `§` markers are unbalanced.
    """
    parts = raw.split(MARKER)
    if len(parts) % 2 == 0:
        raise ValueError("unbalanced § markers - each injection position needs an opening "
                         "and closing §")
    if len(parts) == 1:
        raise ValueError("no § injection positions found in the request")
    literals = parts[0::2]          # n+1 literal segments
    bases = parts[1::2]             # n original values (used to fill non-attacked slots)
    return literals, bases


def build_request(literals: list[str], values: list[str]) -> str:
    """Interleave literal segments with injected values back into a raw request."""
    out = literals[0]
    for i, v in enumerate(values):
        out += v + literals[i + 1]
    return out


def _rows(n_positions: int, bases: list[str], payload_sets: list[list[str]],
          mode: str) -> list[list[str]]:
    """The per-request value lists (one entry per position) for an attack mode."""
    if mode not in ATTACK_MODES:
        raise ValueError(f"mode must be one of {ATTACK_MODES}, got {mode!r}")
    if not payload_sets or not payload_sets[0]:
        raise ValueError("at least one non-empty payload list is required")

    if mode == "sniper":
        pset = payload_sets[0]
        return [[*bases[:i], p, *bases[i + 1:]] for i in range(n_positions) for p in pset]
    if mode == "batteringram":
        return [[p] * n_positions for p in payload_sets[0]]
    # pitchfork / clusterbomb need one payload list per position
    if len(payload_sets) < n_positions:
        raise ValueError(f"{mode} needs one payload list per position "
                         f"({n_positions}); got {len(payload_sets)}")
    sets = payload_sets[:n_positions]
    if mode == "pitchfork":
        length = min(len(s) for s in sets)
        return [[sets[i][j] for i in range(n_positions)] for j in range(length)]
    return [list(combo) for combo in itertools.product(*sets)]   # clusterbomb


def plan_requests(raw: str, payload_sets: list[list[str]], mode: str, *,
                  url_encode: bool = False) -> list[tuple[list[str], str]]:
    """Pure planner: return [(payloads, raw_request), ...] for the whole attack (no I/O)."""
    literals, bases = extract_positions(raw)
    rows = _rows(len(bases), bases, payload_sets, mode)
    out: list[tuple[list[str], str]] = []
    for values in rows:
        injected = [quote(v, safe="") for v in values] if url_encode else values
        out.append((values, build_request(literals, injected)))
    return out


@dataclass
class IntruderResult:
    index: int
    payloads: list[str]
    status: int | None = None
    length: int | None = None
    elapsed_ms: float = 0.0
    matched: bool = False
    error: str | None = None
    anomaly: bool = False        # set during ranking: deviates from the baseline response


@dataclass
class IntruderReport:
    mode: str
    total: int
    results: list[IntruderResult] = field(default_factory=list)
    baseline: tuple[int | None, int | None] | None = None   # the modal (status, length)

    def interesting(self) -> list[IntruderResult]:
        """Results worth a look: anomalies or grep matches, most-deviant first."""
        return sorted((r for r in self.results if r.anomaly or r.matched),
                      key=lambda r: (not r.matched, r.length or 0))


def _rank(results: list[IntruderResult]) -> tuple[int | None, int | None] | None:
    """Flag results whose (status, length) differ from the most common - the outliers."""
    keyed = [(r.status, r.length) for r in results if r.error is None]
    if not keyed:
        return None
    baseline = Counter(keyed).most_common(1)[0][0]
    for r in results:
        if r.error is None and (r.status, r.length) != baseline:
            r.anomaly = True
    return baseline


async def run_intruder(
    raw: str,
    payload_sets: list[list[str]],
    mode: str,
    validator: ScopeValidator,
    *,
    match: str | None = None,
    url_encode: bool = False,
    scheme: str = "https",
    concurrency: int = 10,
    max_requests: int = DEFAULT_MAX_REQUESTS,
    sender: Callable[[RequestSpec], Awaitable[ReplayResult]] | None = None,
) -> IntruderReport:
    """Run the attack: generate requests, send each scope-checked + concurrently, rank.

    ``sender`` is injectable for testing; by default each request goes through the
    scope-enforced ``replay`` path.
    """
    plan = plan_requests(raw, payload_sets, mode, url_encode=url_encode)
    if len(plan) > max_requests:
        raise ValueError(f"{len(plan)} requests exceeds the {max_requests} cap "
                         "(raise --max-requests or narrow the payloads)")

    async def _send(spec: RequestSpec) -> ReplayResult:
        if sender is not None:
            return await sender(spec)
        return await replay(spec, validator, follow_redirects=False)

    sem = asyncio.Semaphore(max(1, concurrency))

    async def _one(index: int, payloads: list[str], raw_request: str) -> IntruderResult:
        async with sem:
            try:
                spec = parse_raw_http(raw_request, default_scheme=scheme)
            except ValueError as exc:
                return IntruderResult(index, payloads, error=f"build error: {exc}")
            res = await _send(spec)
            body = res.body or ""
            return IntruderResult(
                index=index, payloads=payloads,
                status=res.status, length=len(body) if res.ok else None,
                elapsed_ms=res.elapsed_ms,
                matched=bool(match) and match in body,
                error=res.error,
            )

    results = await asyncio.gather(*[
        _one(i, payloads, raw_request) for i, (payloads, raw_request) in enumerate(plan)
    ])
    baseline = _rank(results)
    return IntruderReport(mode=mode, total=len(results), results=results, baseline=baseline)


__all__ = [
    "MARKER", "ATTACK_MODES", "extract_positions", "build_request", "plan_requests",
    "run_intruder", "IntruderResult", "IntruderReport",
]
