"""Consolidated remediation runbook (`orthrus runbook`).

The builder is pure — it collapses findings into shared fix actions and ranks a
path-breaking fix above an isolated one. Tests cover the grouping, the ordering,
the Markdown, and the CLI.
"""

from __future__ import annotations

import asyncio

from click.testing import CliRunner

from orthrus import main
from orthrus.core.schemas import Finding, Severity
from orthrus.db.store import Store
from orthrus.reporting.runbook import build_runbook


def _f(vt: str, sev: Severity, url: str, **kw) -> Finding:
    return Finding(vuln_type=vt, title=kw.pop("title", vt), severity=sev, url=url, **kw)


# --- builder: grouping ---------------------------------------------------

def test_same_vuln_type_collapses_into_one_action_spanning_urls():
    rows = [
        _f("sqli", Severity.HIGH, "http://t/a", title="SQL injection"),
        _f("sqli", Severity.CRITICAL, "http://t/b", title="SQL injection"),
        _f("sqli", Severity.MEDIUM, "http://t/a", title="SQL injection"),  # dup URL
    ]
    rb = build_runbook(rows)
    assert len(rb.actions) == 1
    act = rb.actions[0]
    assert act.vuln_type == "sqli"
    assert act.count == 3
    assert act.urls == ["http://t/a", "http://t/b"]  # distinct + sorted
    assert act.severity == "critical"  # worst in the group


def test_representative_title_and_fullest_remediation_chosen():
    rows = [
        _f("xss", Severity.MEDIUM, "http://t/1", title="XSS", remediation="Encode output."),
        _f("xss", Severity.MEDIUM, "http://t/2", title="XSS",
           remediation="Encode output on every sink and set a strict CSP header."),
    ]
    act = build_runbook(rows).actions[0]
    assert act.title == "XSS"
    assert "strict CSP" in act.remediation  # the fuller of the two


def test_cwe_taken_from_first_finding_that_has_one():
    rows = [
        _f("idor", Severity.HIGH, "http://t/1"),
        _f("idor", Severity.HIGH, "http://t/2", cwe="CWE-639"),
    ]
    assert build_runbook(rows).actions[0].cwe == "CWE-639"


# --- builder: ordering by leverage --------------------------------------

def test_path_breaking_action_sorts_first_even_below_peak_severity():
    # ssrf + exposed-service on one host => the "SSRF -> internal-service" chain.
    rows = [
        _f("ssrf", Severity.HIGH, "http://t/fetch"),
        _f("exposed-service", Severity.HIGH, "http://t/admin"),
        # A lone critical with no chain — higher severity, but breaks no path.
        _f("cmd-injection", Severity.CRITICAL, "http://other/x"),
    ]
    rb = build_runbook(rows)
    assert rb.path_breaking >= 1
    first = rb.actions[0]
    assert first.on_attack_path is True
    assert first.breaks_paths  # carries the human-readable chain signature
    # the isolated critical is present but ranked below the path-breakers
    types = [a.vuln_type for a in rb.actions]
    assert types.index("cmd-injection") > 0


def test_isolated_findings_order_by_severity_then_count():
    rows = [
        _f("a", Severity.LOW, "http://t/1"),
        _f("b", Severity.HIGH, "http://t/1"),
        _f("c", Severity.MEDIUM, "http://t/1"),
        _f("c", Severity.MEDIUM, "http://t/2"),
    ]
    order = [a.vuln_type for a in build_runbook(rows).actions]
    assert order == ["b", "c", "a"]  # high, then medium(x2), then low


# --- builder: markdown + summary ----------------------------------------

def test_markdown_has_title_summary_actions_and_affected():
    rows = [_f("sqli", Severity.CRITICAL, "http://t/a", title="SQL injection",
               remediation="Use parameterised queries.")]
    md = build_runbook(rows, target="http://t").to_markdown()
    assert md.startswith("# Remediation Runbook — http://t")
    assert "1 finding(s) collapse into 1 fix action(s)" in md
    assert "## 1. SQL injection — CRITICAL" in md
    assert "Use parameterised queries." in md
    assert "`http://t/a`" in md


def test_markdown_flags_path_breaker():
    rows = [
        _f("ssrf", Severity.HIGH, "http://t/fetch"),
        _f("exposed-service", Severity.HIGH, "http://t/admin"),
    ]
    md = build_runbook(rows).to_markdown()
    assert "Breaks attack path:" in md
    assert "ssrf" in md and "⇒" in md


def test_empty_findings_is_graceful():
    rb = build_runbook([])
    assert rb.actions == []
    assert "no remediable findings" in rb.summary()
    assert "No findings require remediation." in rb.to_markdown()


def test_url_list_is_capped_with_remainder_note():
    rows = [_f("headers", Severity.LOW, f"http://t/p{i}", title="Missing header") for i in range(20)]
    md = build_runbook(rows).to_markdown()
    assert "and 5 more." in md  # 20 endpoints, 15 shown


# --- CLI -----------------------------------------------------------------

def _db_url(tmp_path) -> str:
    return f"sqlite+aiosqlite:///{(tmp_path / 'h.db').as_posix()}"


def _seed(db_url: str) -> None:
    async def run():
        store = Store(db_url)
        await store.init()
        await store.create_scan("s", "http://t", {}, {})
        await store.add_finding(
            "s", _f("sqli", Severity.CRITICAL, "http://t/q", title="SQL injection",
                    remediation="Use parameterised queries."))
        await store.add_finding(
            "s", _f("headers", Severity.LOW, "http://t/", title="Missing security headers"))
        await store.close()

    asyncio.run(run())


def test_cli_runbook_prints_markdown(tmp_path, monkeypatch):
    _seed(_db_url(tmp_path))
    monkeypatch.setenv("ORTHRUS_DB_URL", _db_url(tmp_path))
    r = CliRunner().invoke(main.cli, ["--no-banner", "runbook", "--scan-id", "s"])
    assert r.exit_code == 0, r.output
    assert "# Remediation Runbook — http://t" in r.output
    assert "SQL injection" in r.output


def test_cli_runbook_min_severity_filters(tmp_path, monkeypatch):
    _seed(_db_url(tmp_path))
    monkeypatch.setenv("ORTHRUS_DB_URL", _db_url(tmp_path))
    r = CliRunner().invoke(
        main.cli, ["--no-banner", "runbook", "--scan-id", "s", "--min-severity", "high"]
    )
    assert r.exit_code == 0, r.output
    assert "SQL injection" in r.output
    assert "Missing security headers" not in r.output  # low filtered out


def test_cli_runbook_writes_output_file(tmp_path, monkeypatch):
    _seed(_db_url(tmp_path))
    monkeypatch.setenv("ORTHRUS_DB_URL", _db_url(tmp_path))
    out = tmp_path / "runbook.md"
    r = CliRunner().invoke(
        main.cli, ["--no-banner", "runbook", "--scan-id", "s", "-o", str(out)]
    )
    assert r.exit_code == 0, r.output
    assert out.exists()
    assert "# Remediation Runbook" in out.read_text(encoding="utf-8")


def test_cli_runbook_json(tmp_path, monkeypatch):
    _seed(_db_url(tmp_path))
    monkeypatch.setenv("ORTHRUS_DB_URL", _db_url(tmp_path))
    r = CliRunner().invoke(main.cli, ["--no-banner", "runbook", "--scan-id", "s", "--json"])
    assert r.exit_code == 0, r.output
    assert '"action_count": 2' in r.output


def test_cli_runbook_unknown_scan(tmp_path, monkeypatch):
    _seed(_db_url(tmp_path))
    monkeypatch.setenv("ORTHRUS_DB_URL", _db_url(tmp_path))
    r = CliRunner().invoke(main.cli, ["--no-banner", "runbook", "--scan-id", "nope"])
    assert r.exit_code == 0  # graceful: logs error, emits nothing
    assert "# Remediation Runbook" not in r.output
