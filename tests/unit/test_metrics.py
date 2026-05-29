"""Tests for per-scanner metric aggregation (pure logic) and orchestrator wiring."""

from __future__ import annotations

from types import SimpleNamespace

from hydra.core.config import ScanConfig, ScopeConfig, Settings
from hydra.core.metrics import ScannerMetric, top_scanners, totals
from hydra.core.orchestrator import Orchestrator
from hydra.core.schemas import Aggressiveness


def test_requests_per_second():
    m = ScannerMetric(name="x", requests=50, duration_s=2.0)
    assert m.requests_per_second == 25.0


def test_requests_per_second_zero_duration_is_safe():
    m = ScannerMetric(name="x", requests=5, duration_s=0.0)
    assert m.requests_per_second == 0.0  # no divide-by-zero


def test_summary_line_plain_and_error():
    ok = ScannerMetric(name="sqli", findings=2, requests=40, duration_s=1.5)
    assert ok.summary_line() == "sqli: findings=2 requests=40 time=1.50s"
    crashed = ScannerMetric(name="xss", findings=0, requests=3, duration_s=0.2, error="ValueError")
    assert crashed.summary_line().endswith("error=ValueError")


def test_top_scanners_default_by_findings():
    metrics = [
        ScannerMetric(name="a", findings=1, requests=100),
        ScannerMetric(name="b", findings=5, requests=10),
        ScannerMetric(name="c", findings=5, requests=50),
    ]
    ranked = [m.name for m in top_scanners(metrics)]
    # b and c tie on findings (5); c wins the requests tiebreak, then a last
    assert ranked == ["c", "b", "a"]


def test_top_scanners_by_requests():
    metrics = [
        ScannerMetric(name="a", findings=1, requests=100),
        ScannerMetric(name="b", findings=5, requests=10),
    ]
    assert [m.name for m in top_scanners(metrics, by="requests")] == ["a", "b"]


def test_top_scanners_by_duration():
    metrics = [
        ScannerMetric(name="slow", duration_s=9.0),
        ScannerMetric(name="fast", duration_s=0.1),
    ]
    assert [m.name for m in top_scanners(metrics, by="duration")] == ["slow", "fast"]


def test_top_scanners_does_not_mutate_input():
    metrics = [ScannerMetric(name="a", findings=1), ScannerMetric(name="b", findings=2)]
    original = list(metrics)
    top_scanners(metrics)
    assert metrics == original  # sorted() returns a new list


def test_totals_aggregates_and_counts_crashes():
    metrics = [
        ScannerMetric(name="a", findings=2, requests=10, duration_s=1.0),
        ScannerMetric(name="b", findings=3, requests=20, duration_s=2.0, error="RuntimeError"),
        ScannerMetric(name="c", findings=0, requests=5, duration_s=0.5, error="TimeoutError"),
    ]
    agg = totals(metrics)
    assert agg.name == "total"
    assert agg.findings == 5
    assert agg.requests == 35
    assert agg.duration_s == 3.5
    assert agg.error == "2 crashed"


def test_totals_no_crashes_has_no_error():
    metrics = [ScannerMetric(name="a", findings=1, requests=2, duration_s=0.3)]
    assert totals(metrics).error is None


def test_totals_empty():
    agg = totals([])
    assert agg.findings == 0 and agg.requests == 0 and agg.error is None


# ------------------------------------------ orchestrator run_scan instrumentation
class _Sev:
    value = "high"


def _finding(fid: str) -> SimpleNamespace:
    return SimpleNamespace(id=fid, vuln_type="xss", severity=_Sev(), url="http://h/x")


class _GoodScanner:
    name = "good"
    min_aggressiveness = Aggressiveness.PASSIVE

    def __init__(self, http: SimpleNamespace) -> None:
        self._http = http

    def applicable(self, ctx: object) -> bool:
        return True

    async def setup(self, ctx: object) -> None:
        pass

    async def teardown(self, ctx: object) -> None:
        pass

    async def scan(self, ctx: object):
        for i in range(3):
            self._http.requests_sent += 1
            yield _finding(f"g{i}")


class _CrashScanner:
    name = "crasher"
    min_aggressiveness = Aggressiveness.PASSIVE

    def __init__(self, http: SimpleNamespace) -> None:
        self._http = http

    def applicable(self, ctx: object) -> bool:
        return True

    async def setup(self, ctx: object) -> None:
        pass

    async def teardown(self, ctx: object) -> None:
        pass

    async def scan(self, ctx: object):
        self._http.requests_sent += 2
        yield _finding("c0")
        self._http.requests_sent += 1
        raise RuntimeError("boom")


class _Store:
    def __init__(self) -> None:
        self.logs: list[tuple[str, str]] = []
        self._id = 0

    async def add_finding(self, scan_id: str, finding: object) -> int:
        self._id += 1
        return self._id

    async def log(self, scan_id: str, level: str, module: str, message: str) -> None:
        self.logs.append((module, message))

    async def set_scan_phase(self, scan_id: str, phase: str) -> None:
        pass  # orchestrator checkpoints the phase after run_scan; no-op for this fake


async def test_run_scan_records_metrics_and_isolates_crash(monkeypatch):
    config = ScanConfig(target="http://h", scope=ScopeConfig(domains=["h"]))
    orch = Orchestrator(config, Settings())
    http = SimpleNamespace(requests_sent=0)
    orch.ctx = SimpleNamespace(http=http, findings=[], finding_ids={})
    orch.store = _Store()
    monkeypatch.setattr(
        "hydra.core.orchestrator.get_scanners",
        lambda modules: [_GoodScanner(http), _CrashScanner(http)],
    )

    total = await orch.run_scan()

    # crasher's RuntimeError is swallowed: the phase still completes, and the
    # finding it yielded before crashing is kept.
    assert total == 4  # 3 from good + 1 from crasher before the exception
    by_name = {m.name: m for m in orch.scanner_metrics}
    assert set(by_name) == {"good", "crasher"}
    assert by_name["good"].findings == 3
    assert by_name["good"].requests == 3
    assert by_name["good"].error is None
    assert by_name["crasher"].findings == 1
    assert by_name["crasher"].requests == 3  # 2 + 1 sent before raising
    assert by_name["crasher"].error == "RuntimeError"
    # one metrics line persisted to the scan log per scanner that ran
    assert sum(1 for module, _ in orch.store.logs if module == "metrics") == 2

