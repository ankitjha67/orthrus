"""The scan summary surfaces triage + attack paths inline (print_summary)."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.orchestrator import Orchestrator, console


def _f(vuln_type, url, severity="high"):
    return SimpleNamespace(vuln_type=vuln_type, url=url, severity=severity)


def _run_analysis(findings):
    stub = SimpleNamespace(ctx=SimpleNamespace(findings=findings))
    with console.capture() as cap:
        Orchestrator._print_analysis(stub)
    return cap.get()


def test_summary_renders_attack_paths_and_triage():
    findings = [
        _f("ssrf", "https://app.test/fetch"),
        _f("exposed-service", "https://app.test:6379/"),
        _f("idor", "https://app.test/order/1"),
        _f("idor", "https://app.test/order/2"),  # duplicate → triage folds
    ]
    out = _run_analysis(findings)
    assert "ATTACK PATHS" in out
    assert "SSRF" in out and "internal-service" in out
    assert "ssrf" in out and "exposed-service" in out  # the step chain
    assert "Triaged" in out and "folded" in out


def test_summary_quiet_when_no_chains():
    out = _run_analysis([_f("security-headers", "https://app.test/", "low")])
    assert "ATTACK PATHS" not in out


def test_summary_no_findings_prints_nothing():
    stub = SimpleNamespace(ctx=SimpleNamespace(findings=[]))
    with console.capture() as cap:
        Orchestrator._print_analysis(stub)
    assert cap.get().strip() == ""
