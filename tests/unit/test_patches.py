"""Automated remediation patch generation (`orthrus patch`)."""

from __future__ import annotations

import asyncio

import httpx
from click.testing import CliRunner

from orthrus import main
from orthrus.core.schemas import Finding, Severity
from orthrus.db.store import Store
from orthrus.reporting.patches import (
    build_patch_prompt,
    build_patch_report,
    llm_patch,
    normalize_vuln_type,
    parse_patch_response,
    patches_for,
)


def _f(vt: str, sev: Severity = Severity.HIGH, url: str = "http://t/x", **kw) -> Finding:
    return Finding(vuln_type=vt, title=kw.pop("title", vt), severity=sev, url=url, **kw)


# --- template library ----------------------------------------------------

def test_patches_for_known_type():
    ps = patches_for("security-headers")
    assert ps and any(p.platform == "nginx" for p in ps)
    assert all(p.body for p in ps)


def test_vuln_type_aliases_normalize():
    assert normalize_vuln_type("reflected-xss") == "xss"
    assert normalize_vuln_type("dom-xss") == "xss"
    assert normalize_vuln_type("path-traversal") == "lfi"
    assert patches_for("stored-xss") == patches_for("xss")  # alias resolves to same list


def test_unknown_type_has_no_template():
    assert patches_for("totally-unknown") == []


def test_cloud_findings_get_terraform_patches():
    assert any(p.language == "hcl" for p in patches_for("cloud-public-bucket"))


# --- grouping + report ---------------------------------------------------

def test_xss_variants_collapse_into_one_group():
    findings = [_f("reflected-xss", url="http://t/a"), _f("dom-xss", url="http://t/b"),
                _f("stored-xss", url="http://t/c")]
    report = build_patch_report(findings)
    xss = [g for g in report.groups if g.vuln_type == "xss"]
    assert len(xss) == 1 and xss[0].count == 3 and len(xss[0].urls) == 3
    assert xss[0].has_patch


def test_patched_groups_sort_before_unpatched():
    findings = [_f("totally-unknown", Severity.CRITICAL), _f("security-headers", Severity.LOW)]
    report = build_patch_report(findings)
    # security-headers has a template (LOW) → ranks above the unpatched CRITICAL unknown.
    assert report.groups[0].vuln_type == "security-headers"
    assert report.patched == 1


def test_report_summary_and_markdown_has_code_fence():
    findings = [_f("sqli", Severity.CRITICAL, remediation="Use parameterized queries.")]
    report = build_patch_report(findings, target="http://t")
    assert "1 with a concrete patch" in report.summary()
    md = report.to_markdown()
    assert md.startswith("# Remediation Patches — http://t")
    assert "```python" in md and "parameterized queries" in md.lower()


def test_unpatched_type_still_shows_remediation():
    findings = [_f("some-novel-bug", remediation="Do the fix.")]
    md = build_patch_report(findings).to_markdown()
    assert "Do the fix." in md
    assert "No templated patch" in md


def test_report_to_dict():
    d = build_patch_report([_f("cors")]).to_dict()
    assert d["fix_types"] == 1 and d["patched"] == 1
    assert d["groups"][0]["patches"]


# --- LLM enrichment (pure parse + fake transport) ------------------------

def test_build_patch_prompt_mentions_finding():
    p = build_patch_prompt(_f("ssrf", url="http://t/fetch"))
    assert "ssrf" in p and "http://t/fetch" in p


def test_parse_patch_response_extracts_fence():
    patch = parse_patch_response("Sure:\n```python\nx = 1\n```\ndone")
    assert patch is not None and patch.language == "python" and patch.body == "x = 1"
    assert parse_patch_response("no code here") is None


class _FakeResp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload

    def json(self):
        return self._payload


def _fake_client(status, payload):
    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, headers=None):
            return _FakeResp(status, payload)

    return _Client


def test_llm_patch_success(monkeypatch):
    payload = {"content": [{"type": "text", "text": "```hcl\nblock_public_acls = true\n```"}]}
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client(200, payload))
    patch = asyncio.run(llm_patch(_f("cloud-public-bucket"), "key"))
    assert patch is not None and patch.language == "hcl" and patch.platform == "ai"


def test_llm_patch_non_200_returns_none(monkeypatch):
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client(500, {}))
    assert asyncio.run(llm_patch(_f("sqli"), "key")) is None


# --- CLI -----------------------------------------------------------------

def _db_url(tmp_path) -> str:
    return f"sqlite+aiosqlite:///{(tmp_path / 'h.db').as_posix()}"


def _seed(db_url: str) -> None:
    async def run():
        store = Store(db_url)
        await store.init()
        await store.create_scan("s", "http://t", {}, {})
        await store.add_finding("s", _f("sqli", Severity.CRITICAL, title="SQL injection",
                                        remediation="Use parameterized queries."))
        await store.add_finding("s", _f("security-headers", Severity.LOW, title="Missing headers"))
        await store.close()

    asyncio.run(run())


def test_cli_patch_prints_markdown(tmp_path, monkeypatch):
    _seed(_db_url(tmp_path))
    monkeypatch.setenv("ORTHRUS_DB_URL", _db_url(tmp_path))
    r = CliRunner().invoke(main.cli, ["--no-banner", "patch", "--scan-id", "s"])
    assert r.exit_code == 0, r.output
    assert "# Remediation Patches" in r.output
    assert "```" in r.output  # at least one code fence


def test_cli_patch_json_and_vuln_type_filter(tmp_path, monkeypatch):
    _seed(_db_url(tmp_path))
    monkeypatch.setenv("ORTHRUS_DB_URL", _db_url(tmp_path))
    r = CliRunner().invoke(
        main.cli, ["--no-banner", "patch", "--scan-id", "s", "--vuln-type", "sqli", "--json"]
    )
    assert r.exit_code == 0, r.output
    assert '"fix_types": 1' in r.output and '"sqli"' in r.output


def test_cli_patch_writes_file(tmp_path, monkeypatch):
    _seed(_db_url(tmp_path))
    monkeypatch.setenv("ORTHRUS_DB_URL", _db_url(tmp_path))
    out = tmp_path / "patches.md"
    r = CliRunner().invoke(main.cli, ["--no-banner", "patch", "--scan-id", "s", "-o", str(out)])
    assert r.exit_code == 0, r.output
    assert "# Remediation Patches" in out.read_text(encoding="utf-8")


def test_cli_patch_unknown_scan(tmp_path, monkeypatch):
    _seed(_db_url(tmp_path))
    monkeypatch.setenv("ORTHRUS_DB_URL", _db_url(tmp_path))
    r = CliRunner().invoke(main.cli, ["--no-banner", "patch", "--scan-id", "nope"])
    assert r.exit_code == 0
    assert "# Remediation Patches" not in r.output
