"""Framework debug / management-endpoint exposure scanner.

Covers the content-fingerprint and debug-mode detectors (200-gated, marker-based
to avoid false positives) and the scanner end-to-end against duck-typed fakes.
"""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Severity
from orthrus.scanners.framework_debug import (
    FrameworkDebugScanner,
    detect_debug_mode,
    match_probe,
    origins_from,
)


# ------------------------------------------------------------- pure detectors
def test_match_probe_requires_200_and_signature() -> None:
    assert match_probe(("propertySources",), 200, '{"propertySources":[]}') is True
    assert match_probe(("PHP Version",), 200, "<h1>PHP Version 8.2</h1>") is True
    assert match_probe(("propertySources",), 404, '{"propertySources":[]}') is False  # not 200
    assert match_probe(("propertySources",), 200, "not found") is False  # no signature


def test_detect_debug_mode_on_known_markers() -> None:
    assert detect_debug_mode("...Traceback (most recent call last):...") is not None
    assert "Werkzeug" in (detect_debug_mode("Werkzeug Debugger: error") or "")
    assert detect_debug_mode("<html>generic 404 not found</html>") is None


def test_origins_from_dedupes_by_scheme_host() -> None:
    out = origins_from("http://h/a", ["http://h/b", "https://h2/c", "http://h/d"])
    assert out == ["http://h", "https://h2"]


# ------------------------------------------------------------ scanner harness
class FakeResp:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text


def _ctx(http: object) -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(target="http://h/"),
        endpoints=[],
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        http=http,
    )


class ExposedHttp:
    """Serves an exposed actuator env + server-status, normal 404 otherwise."""

    async def get(self, url: str, **kw: object) -> FakeResp:
        if url.endswith("/actuator/env"):
            return FakeResp(200, '{"propertySources":[{"name":"systemEnvironment"}]}')
        if url.endswith("/server-status"):
            return FakeResp(200, "Apache Server Status for h\nServer uptime: 3 days\n")
        return FakeResp(404, "<html>not found</html>")


class DebugModeHttp:
    """Returns a Werkzeug stack trace on the bogus error-probe path."""

    async def get(self, url: str, **kw: object) -> FakeResp:
        return FakeResp(500, "Werkzeug Debugger\nTraceback (most recent call last):")


class CleanHttp:
    async def get(self, url: str, **kw: object) -> FakeResp:
        return FakeResp(404, "<html>nothing to see</html>")


async def test_scanner_flags_exposed_endpoints() -> None:
    findings = [f async for f in FrameworkDebugScanner().scan(_ctx(ExposedHttp()))]
    fw = [f for f in findings if f.vuln_type == "framework-debug"]
    titles = " ".join(f.title for f in fw)
    assert "Actuator (env)" in titles
    assert "server-status" in titles
    # the env endpoint is rated HIGH
    assert any(f.severity == Severity.HIGH for f in fw if "env" in f.title)


async def test_scanner_flags_debug_mode_stack_trace() -> None:
    findings = [f async for f in FrameworkDebugScanner().scan(_ctx(DebugModeHttp()))]
    dbg = [f for f in findings if "Debug mode enabled" in f.title]
    assert len(dbg) == 1
    assert dbg[0].severity == Severity.HIGH
    assert dbg[0].cwe == "CWE-489"


async def test_scanner_quiet_when_nothing_exposed() -> None:
    findings = [f async for f in FrameworkDebugScanner().scan(_ctx(CleanHttp()))]
    assert [f for f in findings if f.vuln_type == "framework-debug"] == []
