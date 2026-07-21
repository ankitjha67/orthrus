"""Slack / Jira notification integrations (`orthrus notify`).

The payload *builders* are pure and get the bulk of the coverage; the async
senders are exercised against a fake httpx transport so no network is touched.
"""

from __future__ import annotations

import asyncio

import httpx
from click.testing import CliRunner

from orthrus import main
from orthrus.core.schemas import Finding, Severity
from orthrus.db.store import Store
from orthrus.integrations import notify


def _f(sev: Severity, vuln="sqli", title="SQL injection", url="http://t/q", **kw) -> Finding:
    return Finding(vuln_type=vuln, title=title, severity=sev, url=url, **kw)


# --- pure builders -------------------------------------------------------

def test_at_or_above_filters_and_sorts_worst_first():
    rows = [_f(Severity.LOW), _f(Severity.CRITICAL), _f(Severity.MEDIUM), _f(Severity.HIGH)]
    kept = notify.at_or_above(rows, "high")
    sev = [r.severity for r in kept]
    assert sev == [Severity.CRITICAL, Severity.HIGH]  # low + medium dropped, worst-first


def test_at_or_above_accepts_plain_string_severity():
    class Row:
        severity = "critical"
    assert len(notify.at_or_above([Row()], "high")) == 1


def test_slack_message_has_text_tallies_and_capped_items():
    rows = [_f(Severity.CRITICAL, title=f"crit-{i}") for i in range(25)]
    rows.append(_f(Severity.LOW, title="a-low"))
    msg = notify.slack_message("scan1", "http://t", rows, min_severity="high", max_items=20)
    text = msg["text"]
    assert "scan1" in text and "http://t" in text
    assert "25 critical" in text  # tally counts every row, not just the shown ones
    assert "and 5 more" in text  # 25 crit selected, 20 shown → 5 elided
    assert "a-low" not in text  # below the 'high' floor


def test_slack_message_no_qualifying_findings_still_builds():
    msg = notify.slack_message("s", "http://t", [_f(Severity.LOW)], min_severity="high")
    assert "0 at or above" in msg["text"]


def test_jira_issue_payload_shape():
    row = _f(Severity.CRITICAL, cwe="CWE-89", description="d", remediation="use params")
    issue = notify.jira_issue(row, "SEC", "scan1")["fields"]
    assert issue["project"]["key"] == "SEC"
    assert issue["summary"].startswith("[ORTHRUS] ")
    assert issue["issuetype"]["name"] == "Bug"
    assert issue["priority"]["name"] == "Highest"  # critical → Highest
    assert "sev-critical" in issue["labels"] and "sqli" in issue["labels"]
    assert "CWE-89" in issue["description"] and "use params" in issue["description"]


def test_jira_summary_is_truncated():
    row = _f(Severity.HIGH, title="x" * 400)
    assert len(notify.jira_issue(row, "SEC", "s")["fields"]["summary"]) <= 250


# --- async senders (fake transport, no network) --------------------------

class _Recorder:
    def __init__(self, *, json_data=None, raise_status=False):
        self.posts: list[dict] = []
        self.client_kwargs: list[dict] = []
        self._json = json_data or {}
        self._raise = raise_status

    def client(self):
        rec = self

        class _Resp:
            def raise_for_status(self):
                if rec._raise:
                    raise httpx.HTTPError("boom")

            def json(self):
                return rec._json

        class _Client:
            def __init__(self, *a, **k):
                rec.client_kwargs.append(k)

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, url, json=None):
                rec.posts.append({"url": url, "json": json})
                return _Resp()

        return _Client


def test_send_slack_success(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(notify.httpx, "AsyncClient", rec.client())
    ok = asyncio.run(notify.send_slack("http://hook", {"text": "hi"}))
    assert ok is True
    assert rec.posts == [{"url": "http://hook", "json": {"text": "hi"}}]


def test_send_slack_failure_is_swallowed(monkeypatch):
    rec = _Recorder(raise_status=True)
    monkeypatch.setattr(notify.httpx, "AsyncClient", rec.client())
    assert asyncio.run(notify.send_slack("http://hook", {"text": "hi"})) is False


def test_send_discord_posts_content(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(notify.httpx, "AsyncClient", rec.client())
    ok = asyncio.run(notify.send_discord("http://dhook", "2 NEW assets"))
    assert ok is True
    assert rec.posts == [{"url": "http://dhook", "json": {"content": "2 NEW assets"}}]


def test_send_discord_caps_length_and_swallows_failure(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(notify.httpx, "AsyncClient", rec.client())
    asyncio.run(notify.send_discord("http://dhook", "x" * 5000))
    assert len(rec.posts[0]["json"]["content"]) == 1900     # Discord 2000-char cap

    rec2 = _Recorder(raise_status=True)
    monkeypatch.setattr(notify.httpx, "AsyncClient", rec2.client())
    assert asyncio.run(notify.send_discord("http://dhook", "hi")) is False


def test_create_jira_issues_posts_per_finding_with_auth(monkeypatch):
    rec = _Recorder(json_data={"key": "SEC-1"})
    monkeypatch.setattr(notify.httpx, "AsyncClient", rec.client())
    rows = [_f(Severity.CRITICAL), _f(Severity.HIGH)]
    keys = asyncio.run(
        notify.create_jira_issues("https://acme.atlassian.net/", "a@b.c", "tok", "SEC", rows, "s")
    )
    assert keys == ["SEC-1", "SEC-1"]
    assert len(rec.posts) == 2
    assert rec.posts[0]["url"] == "https://acme.atlassian.net/rest/api/2/issue"
    assert rec.client_kwargs[0]["headers"]["Authorization"].startswith("Basic ")


def test_create_jira_issues_bounded_by_max(monkeypatch):
    rec = _Recorder(json_data={"key": "SEC-1"})
    monkeypatch.setattr(notify.httpx, "AsyncClient", rec.client())
    rows = [_f(Severity.CRITICAL) for _ in range(5)]
    keys = asyncio.run(
        notify.create_jira_issues("http://j", "a@b.c", "t", "SEC", rows, "s", max_issues=2)
    )
    assert len(keys) == 2 and len(rec.posts) == 2


# --- CLI (dry-run prints payloads to stdout, sends nothing) ---------------

def _db_url(tmp_path) -> str:
    return f"sqlite+aiosqlite:///{(tmp_path / 'h.db').as_posix()}"


def _seed(db_url: str, sev: Severity = Severity.CRITICAL) -> None:
    async def run():
        store = Store(db_url)
        await store.init()
        await store.create_scan("s", "http://t", {}, {})
        await store.add_finding("s", _f(sev, title="SQL injection"))
        await store.close()

    asyncio.run(run())


def test_cli_requires_a_destination(tmp_path, monkeypatch):
    _seed(_db_url(tmp_path))
    monkeypatch.setenv("ORTHRUS_DB_URL", _db_url(tmp_path))
    r = CliRunner().invoke(main.cli, ["--no-banner", "notify", "--scan-id", "s"])
    assert r.exit_code != 0
    assert "specify" in (r.output + str(r.exception) + (r.stderr or ""))


def test_cli_slack_dry_run_prints_payload_and_sends_nothing(tmp_path, monkeypatch):
    _seed(_db_url(tmp_path))
    monkeypatch.setenv("ORTHRUS_DB_URL", _db_url(tmp_path))

    def _boom(*a, **k):  # any send attempt must fail the test
        raise AssertionError("dry-run must not send")

    monkeypatch.setattr(notify, "send_slack", _boom)
    r = CliRunner().invoke(
        main.cli, ["--no-banner", "notify", "--scan-id", "s", "--slack", "http://hook", "--dry-run"]
    )
    assert r.exit_code == 0, r.output
    # The emitted Slack payload (stdout) carries the finding; a decorative header may
    # share the stream, so assert on the JSON's content rather than parsing the whole thing.
    assert '"text"' in r.output
    assert "SQL injection" in r.output
    assert "CRITICAL" in r.output


def test_cli_jira_dry_run_prints_issue(tmp_path, monkeypatch):
    _seed(_db_url(tmp_path))
    monkeypatch.setenv("ORTHRUS_DB_URL", _db_url(tmp_path))
    r = CliRunner().invoke(
        main.cli,
        [
            "--no-banner", "notify", "--scan-id", "s", "--dry-run",
            "--jira-url", "http://j", "--jira-user", "a@b.c",
            "--jira-token", "tok", "--jira-project", "SEC",
        ],
    )
    assert r.exit_code == 0, r.output
    assert '"key": "SEC"' in r.output  # project key in the create-issue payload
    assert "[ORTHRUS] SQL injection" in r.output


def test_cli_no_findings_at_severity_emits_no_payload(tmp_path, monkeypatch):
    _seed(_db_url(tmp_path), sev=Severity.LOW)
    monkeypatch.setenv("ORTHRUS_DB_URL", _db_url(tmp_path))
    r = CliRunner().invoke(
        main.cli,
        ["--no-banner", "notify", "--scan-id", "s", "--slack", "http://hook", "--dry-run"],
    )
    assert r.exit_code == 0, r.output
    assert '"text"' not in r.output  # nothing qualified → no Slack payload
