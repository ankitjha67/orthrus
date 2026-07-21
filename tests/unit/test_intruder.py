"""Intruder request fuzzer - position parsing, attack modes, ranking (scope-safe)."""

from __future__ import annotations

import asyncio

import pytest

from orthrus.proxy.intruder import (
    build_request,
    extract_positions,
    plan_requests,
    run_intruder,
)
from orthrus.proxy.replay import ReplayResult

RAW = "GET /item?id=§1§&q=§x§ HTTP/1.1\r\nHost: t.test\r\n\r\n"


def test_extract_positions_and_build():
    literals, bases = extract_positions(RAW)
    assert bases == ["1", "x"]
    assert len(literals) == 3
    # round-trip: injecting the base values reproduces the original (minus the §)
    assert build_request(literals, bases) == RAW.replace("§", "")

    with pytest.raises(ValueError, match="unbalanced"):
        extract_positions("GET /a?x=§1 HTTP/1.1")           # one lone marker
    with pytest.raises(ValueError, match="no § injection"):
        extract_positions("GET /a HTTP/1.1")


def test_attack_modes_generate_the_right_request_sets():
    # sniper: one position at a time -> n_positions * len(payloads)
    sniper = plan_requests(RAW, [["a", "b"]], "sniper")
    assert [p for p, _ in sniper] == [["a", "x"], ["b", "x"], ["1", "a"], ["1", "b"]]

    # battering ram: same payload in every position
    ram = plan_requests(RAW, [["a", "b"]], "batteringram")
    assert [p for p, _ in ram] == [["a", "a"], ["b", "b"]]

    # pitchfork: one list per position, lockstep (min length)
    pitch = plan_requests(RAW, [["a", "b"], ["1", "2", "3"]], "pitchfork")
    assert [p for p, _ in pitch] == [["a", "1"], ["b", "2"]]

    # cluster bomb: cartesian product
    cluster = plan_requests(RAW, [["a", "b"], ["1", "2"]], "clusterbomb")
    assert [p for p, _ in cluster] == [["a", "1"], ["a", "2"], ["b", "1"], ["b", "2"]]

    # url-encode is applied to the injected value in the built request (empty §§ position)
    enc = plan_requests("GET /?x=§§ HTTP/1.1\r\nHost: t\r\n\r\n", [["a b&c"]], "sniper",
                        url_encode=True)
    assert "a%20b%26c" in enc[0][1]


def test_mode_validation():
    with pytest.raises(ValueError, match="one payload list per position"):
        plan_requests(RAW, [["a"]], "pitchfork")            # 2 positions, 1 list
    with pytest.raises(ValueError, match="non-empty payload"):
        plan_requests(RAW, [[]], "sniper")


def test_run_intruder_ranks_anomalies_and_matches():
    # fake sender: the payload 'boom' returns a different status+longer body (the outlier);
    # everything else returns a uniform baseline.
    async def fake_sender(spec):
        body = "ok" * 10
        status = 200
        if "boom" in spec.to_raw():
            body = "ERROR: sql syntax " + "x" * 50
            status = 500
        return ReplayResult(method=spec.method, url=spec.url, status=status, body=body,
                            elapsed_ms=1.0)

    async def run():
        report = await run_intruder(
            "GET /item?id=§1§ HTTP/1.1\r\nHost: t.test\r\n\r\n",
            [["1", "2", "boom", "4"]], "sniper", validator=None,
            match="sql syntax", sender=fake_sender)
        assert report.total == 4
        # baseline is the common (200, len) pair; the 'boom' row deviates
        anomalies = [r for r in report.results if r.anomaly]
        assert len(anomalies) == 1 and anomalies[0].payloads == ["boom"]
        assert anomalies[0].status == 500
        # grep match surfaced it too
        interesting = report.interesting()
        assert interesting and interesting[0].matched and interesting[0].payloads == ["boom"]
        return report

    asyncio.run(run())


def test_run_intruder_respects_max_requests():
    async def run():
        with pytest.raises(ValueError, match="exceeds"):
            await run_intruder(RAW, [["a", "b", "c"], ["1", "2", "3"]], "clusterbomb",
                               validator=None, max_requests=4, sender=_noop)
    asyncio.run(run())


async def _noop(spec):
    return ReplayResult(method=spec.method, url=spec.url, status=200, body="x")
