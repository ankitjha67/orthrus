"""Reachability attack graph: transitive path merging + collapse metric."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.attack_graph import build_attack_graph, correlate_paths


def F(vuln_type, url, severity="medium"):
    return SimpleNamespace(vuln_type=vuln_type, url=url, severity=severity)


def test_two_rules_sharing_a_finding_merge_into_one_path():
    # 'file-read → secret' (lfi→exposed-secret) and 'secret → auth-forgery'
    # (exposed-secret→jwt) share the exposed-secret finding → one 3-step path.
    paths = correlate_paths([
        F("lfi", "https://app.test/download", "high"),
        F("exposed-secret", "https://app.test/.env", "high"),
        F("jwt", "https://app.test/api/login", "medium"),
    ])
    assert len(paths) == 1
    p = paths[0]
    assert [s.vuln_type for s in p.steps] == ["lfi", "exposed-secret", "jwt"]
    assert p.length == 3
    assert p.severity == "critical"  # 'secret → auth-forgery' is a critical rule
    assert len(p.via) == 2  # two rules composed


def test_unrelated_finding_stays_off_path():
    rep = build_attack_graph([
        F("lfi", "https://app.test/download", "high"),
        F("exposed-secret", "https://app.test/.env", "high"),
        F("jwt", "https://app.test/api/login", "medium"),
        F("security-headers", "https://app.test/", "low"),  # not part of any chain
    ])
    assert rep.total_findings == 4
    assert rep.reachable_findings == 3  # the header finding is not reachable
    assert len(rep.paths) == 1


def test_paths_are_host_scoped():
    # Same vuln pair split across two hosts must NOT fabricate a cross-host path.
    paths = correlate_paths([
        F("ssrf", "https://a.test/fetch"),
        F("exposed-service", "https://b.test/redis"),
    ])
    assert paths == []


def test_ssrf_plus_service_on_same_host_is_one_path():
    paths = correlate_paths([
        F("ssrf", "https://app.test/fetch"),
        F("exposed-service", "https://app.test/redis"),
    ])
    assert len(paths) == 1
    assert paths[0].severity == "critical"
    assert [s.vuln_type for s in paths[0].steps] == ["ssrf", "exposed-service"]


def test_no_findings_no_paths():
    rep = build_attack_graph([])
    assert rep.paths == []
    assert "no attack paths" in rep.summary()


def test_summary_reports_collapse():
    rep = build_attack_graph([
        F("lfi", "https://app.test/d", "high"),
        F("exposed-secret", "https://app.test/.env", "high"),
    ])
    s = rep.summary()
    assert "collapsed into 1 attack path" in s


def test_report_to_dict_shape():
    rep = build_attack_graph([
        F("xss", "https://app.test/q", "high"),
        F("csrf", "https://app.test/form", "medium"),
    ])
    d = rep.to_dict()
    assert set(d) == {"summary", "total_findings", "reachable_findings", "path_count", "paths"}
    assert d["path_count"] == len(d["paths"])
    if d["paths"]:
        assert set(d["paths"][0]) == {"host", "severity", "length", "impact", "via", "steps"}
