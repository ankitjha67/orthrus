"""Client-side taint scanner: sink classification + browser-driven scan flow."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Severity
from orthrus.scanners.dom_taint import DomTaintScanner, classify_sink


def test_classify_xss_sinks():
    assert classify_sink("eval") == ("xss", Severity.HIGH, "CWE-79")
    assert classify_sink("innerHTML") == ("xss", Severity.HIGH, "CWE-79")
    assert classify_sink("document.write") == ("xss", Severity.HIGH, "CWE-79")


def test_classify_redirect_sinks():
    assert classify_sink("location.assign") == ("open-redirect", Severity.MEDIUM, "CWE-601")
    assert classify_sink("window.open") == ("open-redirect", Severity.MEDIUM, "CWE-601")


def test_classify_unknown_sink():
    assert classify_sink("console.log") is None


class _FakeBrowser:
    def __init__(self, flows: list[dict]) -> None:
        self._flows = flows
        self.calls: list[str] = []

    async def trace_taint(self, url: str, **kw: object) -> list[dict]:
        self.calls.append(url)
        return self._flows


def _ctx(browser: object) -> SimpleNamespace:
    return SimpleNamespace(
        endpoints=[],
        browser=browser,
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(target="https://h/page"),
    )


async def test_scan_emits_xss_and_redirect_findings():
    flows = [
        {"sink": "eval", "value": "orthrustaintAA"},
        {"sink": "innerHTML", "value": "orthrustaintAA"},
        {"sink": "location.assign", "value": "orthrustaintAA"},
    ]
    findings = [f async for f in DomTaintScanner().scan(_ctx(_FakeBrowser(flows)))]
    kinds = {(f.vuln_type, f.evidence.matched_at) for f in findings}
    assert ("xss", "eval") in kinds
    assert ("xss", "innerHTML") in kinds
    assert ("open-redirect", "location.assign") in kinds


async def test_scan_seeds_canary_in_url():
    fake = _FakeBrowser([])
    [f async for f in DomTaintScanner().scan(_ctx(fake))]
    assert fake.calls and "orthrustaint" in fake.calls[0] and "#" in fake.calls[0]


async def test_scan_noop_without_browser():
    assert [f async for f in DomTaintScanner().scan(_ctx(None))] == []
