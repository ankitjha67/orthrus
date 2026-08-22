"""PortSwigger live-lab eval harness (oracle parser, aggregation, runner)."""

from __future__ import annotations

from orthrus.benchmark.ps_labs import (
    EvalReport,
    LabResult,
    LabSpec,
    check_via_oracle,
    parse_lab_status,
    run_lab_eval,
    solve_rates,
)


# --------------------------------------------------------------- oracle parse
def test_parse_lab_status_css_classes() -> None:
    assert parse_lab_status('<div class="widgetcontainer-lab-status is-solved">Solved</div>') == "solved"
    assert parse_lab_status('<div class="widgetcontainer-lab-status is-notsolved">Not solved</div>') == "notsolved"


def test_parse_lab_status_text_fallback() -> None:
    assert parse_lab_status("<h3>Not solved</h3>") == "notsolved"  # 'not solved' beats 'solved'
    assert parse_lab_status("<h3>Solved</h3>") == "solved"
    assert parse_lab_status("<html>no widget here</html>") == "unknown"


# ---------------------------------------------------------------- aggregation
def test_solve_rates_excludes_unknown_and_error() -> None:
    results = [
        LabResult("a", "sqli", "solved"),
        LabResult("b", "sqli", "notsolved"),
        LabResult("c", "xss", "solved"),
        LabResult("d", "ssrf", "unknown"),
        LabResult("e", "idor", "error"),
    ]
    r = solve_rates(results)
    assert r["scored"] == 3 and r["excluded"] == 2 and r["solved"] == 2
    assert r["overall"] == round(2 / 3, 3)
    assert r["by_class"]["sqli"] == 0.5
    assert r["by_class"]["xss"] == 1.0


def test_solve_rates_all_excluded_is_none() -> None:
    r = solve_rates([LabResult("a", "sqli", "unknown"), LabResult("b", "xss", "error")])
    assert r["overall"] is None and r["scored"] == 0


# --------------------------------------------------------------- oracle check
async def test_check_via_oracle_solved() -> None:
    async def drive(lab: LabSpec) -> None:
        return None

    async def fetch(url: str) -> str:
        return '<div class="is-solved">Solved</div>'

    res = await check_via_oracle(LabSpec("x", "sqli", "http://lab"), drive, fetch)
    assert res.status == "solved"


async def test_check_via_oracle_error_on_failure() -> None:
    async def drive(lab: LabSpec) -> None:
        return None

    async def fetch(url: str) -> str:
        raise RuntimeError("lab instance expired")

    res = await check_via_oracle(LabSpec("x", "sqli", ""), drive, fetch)
    assert res.status == "error"


async def test_run_lab_eval_aggregates() -> None:
    labs = [LabSpec("a", "sqli"), LabSpec("b", "xss")]

    async def check(lab: LabSpec) -> LabResult:
        return LabResult(lab.lab_id, lab.vuln_class, "solved")

    report = await run_lab_eval(labs, check)
    assert isinstance(report, EvalReport)
    assert len(report.results) == 2
    assert report.solve_rate == 1.0
