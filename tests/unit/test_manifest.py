"""Tests for the per-scan reproducibility manifest."""

from __future__ import annotations

import json
from types import SimpleNamespace

from orthrus.risk.manifest import (
    build_manifest,
    canonical_json,
    finding_digest,
    finding_signature,
    sha256_of,
    write_manifest,
)


def _f(vuln_type="xss", url="https://t.example/a?x=1", parameter="q", cwe="CWE-79", severity="high"):
    return SimpleNamespace(vuln_type=vuln_type, url=url, parameter=parameter, cwe=cwe, severity=severity)


def _manifest(**over):
    base = dict(
        tool_version="0.1.0", target="https://t.example", scope_rules=["t.example"],
        config={"aggressiveness": "normal"}, modules=["all"], findings=[_f()],
    )
    base.update(over)
    return build_manifest(**base)


def test_canonical_json_is_key_order_independent():
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})
    assert sha256_of({"a": 1, "b": 2}) == sha256_of({"b": 2, "a": 1})


def test_finding_signature_is_evidence_free_and_stable():
    a = _f()
    b = _f()  # identical identity, different object
    assert finding_signature(a) == finding_signature(b)
    assert finding_signature(_f(parameter="other")) != finding_signature(a)


def test_finding_digest_is_order_independent():
    a, b = _f(vuln_type="xss"), _f(vuln_type="sqli", url="https://t.example/b")
    assert finding_digest([a, b]) == finding_digest([b, a])
    assert finding_digest([a, b])["count"] == 2


def test_manifest_hash_excludes_timestamps():
    # The whole point: a re-run at a different time over the same evidence reproduces the hash.
    m1 = _manifest(started_at="2026-01-01T00:00:00", finished_at="2026-01-01T00:05:00")
    m2 = _manifest(started_at="2026-06-15T12:00:00", finished_at="2026-06-15T12:30:00")
    assert m1.manifest_hash == m2.manifest_hash
    assert m1.duration_seconds == 300.0 and m2.duration_seconds == 1800.0


def test_different_findings_change_the_hash():
    assert _manifest(findings=[_f()]).manifest_hash != _manifest(findings=[_f(), _f(url="https://t.example/b")]).manifest_hash


def test_different_scope_changes_scope_hash_and_manifest_hash():
    a = _manifest(scope_rules=["t.example"])
    b = _manifest(scope_rules=["t.example", "api.t.example"])
    assert a.scope_hash != b.scope_hash and a.manifest_hash != b.manifest_hash


def test_different_config_changes_config_hash_and_manifest_hash():
    a = _manifest(config={"aggressiveness": "normal"})
    b = _manifest(config={"aggressiveness": "aggressive"})
    assert a.config_hash != b.config_hash and a.manifest_hash != b.manifest_hash


def test_duration_is_none_on_unparseable_timestamps():
    assert _manifest(started_at="", finished_at="").duration_seconds is None


def test_write_manifest_round_trips(tmp_path):
    m = _manifest()
    out = tmp_path / "run_manifest.json"
    write_manifest(str(out), m)
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["manifest_hash"] == m.manifest_hash
    assert loaded["findings"]["count"] == 1 and loaded["target"] == "https://t.example"
