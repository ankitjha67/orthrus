"""PortSwigger Web Security Academy live-lab eval harness.

The static benchmark (scorer/metrics) proves detection on a labeled corpus; this
complements it with the harder, less-contaminated signal: run ORTHRUS against a
**live** PortSwigger lab and let the lab's *own* "solved" widget be the oracle.
A lab flips to solved only when the vulnerability is genuinely exploited, so a
solve is end-to-end proof (scan -> confirm -> exploit), not just a text match.

What lives here is the deterministic, testable core:
  - ``parse_lab_status`` reads the lab header widget -> solved / notsolved / unknown.
  - ``solve_rates`` aggregates results into per-class + overall solve rates,
    excluding unreadable/errored labs from the denominator (an expired or
    oracle-unreadable lab must not count as a failure).
  - ``run_lab_eval`` orchestrates, but the two live steps - *drive ORTHRUS at the
    lab* and *fetch the lab page* - are **injected** callables, so the harness is
    unit-testable offline and only touches the network when an operator wires in
    real drivers on their authorised PortSwigger account.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

SOLVED, NOTSOLVED, UNKNOWN, ERROR = "solved", "notsolved", "unknown", "error"


def parse_lab_status(html: str) -> str:
    """Read a PortSwigger lab header widget -> 'solved' | 'notsolved' | 'unknown'."""
    low = (html or "").lower()
    # CSS-class signals are the most reliable. Check is-notsolved first (it does
    # not contain the is-solved substring, but be explicit about precedence).
    if "is-notsolved" in low:
        return NOTSOLVED
    if "is-solved" in low:
        return SOLVED
    # Text fallback ("Not solved" must win over the "solved" it contains).
    if "not solved" in low:
        return NOTSOLVED
    if "solved" in low:
        return SOLVED
    return UNKNOWN


@dataclass(frozen=True)
class LabSpec:
    lab_id: str
    vuln_class: str
    url: str = ""  # per-session instance URL, filled at run time


@dataclass(frozen=True)
class LabResult:
    lab_id: str
    vuln_class: str
    status: str  # solved | notsolved | unknown | error


# A small starting catalogue (operator supplies each lab's per-session URL).
DEFAULT_LAB_CATALOG: tuple[LabSpec, ...] = (
    LabSpec("sqli-login-bypass", "sqli"),
    LabSpec("sqli-union-data-retrieval", "sqli"),
    LabSpec("xss-reflected-basic", "xss"),
    LabSpec("ssrf-basic", "ssrf"),
    LabSpec("idor-user-id-in-url", "idor"),
    LabSpec("access-control-unprotected-admin", "access-control"),
    LabSpec("xxe-file-retrieval", "xxe"),
    LabSpec("ssti-basic", "ssti"),
)


def solve_rates(results: list[LabResult]) -> dict:
    """Per-class + overall solve rate; unknown/errored labs are excluded."""
    scored = [r for r in results if r.status in (SOLVED, NOTSOLVED)]
    by_class: dict[str, list[int]] = {}
    for r in scored:
        bucket = by_class.setdefault(r.vuln_class, [0, 0])  # [solved, total]
        bucket[1] += 1
        if r.status == SOLVED:
            bucket[0] += 1
    solved = sum(1 for r in scored if r.status == SOLVED)
    return {
        "overall": round(solved / len(scored), 3) if scored else None,
        "solved": solved,
        "scored": len(scored),
        "excluded": len(results) - len(scored),  # unknown / error not counted
        "by_class": {k: round(v[0] / v[1], 3) for k, v in sorted(by_class.items())},
    }


@dataclass
class EvalReport:
    results: list[LabResult] = field(default_factory=list)

    @property
    def rates(self) -> dict:
        return solve_rates(self.results)

    @property
    def solve_rate(self) -> float | None:
        return self.rates["overall"]


# drive(lab) -> exploit the lab with ORTHRUS; fetch(url) -> lab page HTML.
Driver = Callable[[LabSpec], Awaitable[None]]
Fetcher = Callable[[str], Awaitable[str]]
Checker = Callable[[LabSpec], Awaitable[LabResult]]


async def check_via_oracle(lab: LabSpec, drive: Driver, fetch: Fetcher) -> LabResult:
    """Drive ORTHRUS at the lab, then read the lab's own solved-widget oracle."""
    try:
        await drive(lab)
        html = await fetch(lab.url)
    except Exception:  # noqa: BLE001 - a broken lab must not abort the whole eval
        return LabResult(lab.lab_id, lab.vuln_class, ERROR)
    return LabResult(lab.lab_id, lab.vuln_class, parse_lab_status(html))


async def run_lab_eval(labs: list[LabSpec], check: Checker) -> EvalReport:
    """Run each lab through the injected ``check`` and aggregate the report."""
    results = [await check(lab) for lab in labs]
    return EvalReport(results=results)


__all__ = [
    "SOLVED",
    "NOTSOLVED",
    "UNKNOWN",
    "ERROR",
    "LabSpec",
    "LabResult",
    "EvalReport",
    "DEFAULT_LAB_CATALOG",
    "parse_lab_status",
    "solve_rates",
    "check_via_oracle",
    "run_lab_eval",
]
