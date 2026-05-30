"""HTTP request smuggling (desync) scanner — timing-based CL.TE / TE.CL."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Severity
from orthrus.scanners.request_smuggling import (
    RequestSmugglingScanner,
    build_cl0_probe,
    build_clte_probe,
    build_tecl_probe,
    cl0_desynced,
    desync_signal,
)


def test_cl0_probe_embeds_marker_request_as_body() -> None:
    raw = build_cl0_probe("h", "MARK123").decode()
    assert raw.startswith("POST / HTTP/1.1")
    assert "GET /MARK123 HTTP/1.1" in raw
    assert "Content-Length: " in raw and "Connection: keep-alive" in raw


def test_cl0_desynced_requires_marker_and_second_response() -> None:
    two = "HTTP/1.1 200 OK\r\n\r\nok\nHTTP/1.1 404 Not Found\r\n\r\n/MARK123 not found"
    assert cl0_desynced(two, "MARK123") is True
    # only one response (body echo) -> not a desync
    one = "HTTP/1.1 200 OK\r\n\r\nyou posted: GET /MARK123 HTTP/1.1"
    assert cl0_desynced(one, "MARK123") is False
    # marker absent -> not a desync
    assert cl0_desynced("HTTP/1.1 200\r\n\r\nHTTP/1.1 200\r\n\r\nok", "MARK123") is False


def test_probes_carry_conflicting_framing() -> None:
    raw = build_clte_probe("h").decode()
    assert "Transfer-Encoding: chunked" in raw and "Content-Length:" in raw
    assert "Host: h" in raw
    assert "Transfer-Encoding: chunked" in build_tecl_probe("h").decode()


def test_desync_signal() -> None:
    # probe stalled to ~timeout while baseline was fast -> signal
    assert desync_signal(0.1, 6.0, 6.0) is True
    # probe fast -> no signal
    assert desync_signal(0.1, 0.2, 6.0) is False
    # baseline itself slow (loaded host) -> suppressed (no FP)
    assert desync_signal(4.0, 6.0, 6.0) is False


def _ctx(scanner_probe, *, in_scope: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(target="http://h/"),
        endpoints=[],
        scope=SimpleNamespace(is_allowed=lambda _u: in_scope),
        http=None,
    )


class _StallScanner(RequestSmugglingScanner):
    """Baseline fast, CL.TE/TE.CL probes stall -> should flag."""

    async def _probe_time(self, host, port, tls, raw, timeout_s):  # type: ignore[override]
        return 0.1 if b"GET /" in raw else timeout_s


class _FastScanner(RequestSmugglingScanner):
    """Everything fast -> no desync."""

    async def _probe_time(self, host, port, tls, raw, timeout_s):  # type: ignore[override]
        return 0.1


class _DeadScanner(RequestSmugglingScanner):
    async def _probe_time(self, host, port, tls, raw, timeout_s):  # type: ignore[override]
        return None  # connection failed


async def test_flags_when_probe_stalls() -> None:
    findings = [f async for f in _StallScanner().scan(_ctx(None))]
    rs = [f for f in findings if f.vuln_type == "request-smuggling"]
    assert len(rs) == 1
    assert rs[0].severity == Severity.HIGH
    assert rs[0].cwe == "CWE-444"


async def test_no_flag_when_all_fast() -> None:
    findings = [f async for f in _FastScanner().scan(_ctx(None))]
    assert [f for f in findings if f.vuln_type == "request-smuggling"] == []


async def test_no_flag_on_dead_host() -> None:
    findings = [f async for f in _DeadScanner().scan(_ctx(None))]
    assert findings == []


async def test_skips_out_of_scope() -> None:
    findings = [f async for f in _StallScanner().scan(_ctx(None, in_scope=False))]
    assert findings == []
