"""Finding dedup + reimport-delta reconciliation."""

from __future__ import annotations

from orthrus.core.schemas import Confidence, Evidence, Finding, ParamLocation, Severity
from orthrus.risk.dedup import (
    dedupe_findings,
    finding_hash,
    reconcile,
)


def F(vuln="sqli", url="http://h/a?id=1", param="id", loc="query", cwe="CWE-89", conf="firm"):
    return {
        "vuln_type": vuln,
        "url": url,
        "parameter": param,
        "param_location": loc,
        "cwe": cwe,
        "confidence": conf,
    }


def test_finding_hash_ignores_query_and_distinguishes_param() -> None:
    # same path+param, different query value -> same identity
    assert finding_hash(F(url="http://h/a?id=1")) == finding_hash(F(url="http://h/a?id=2"))
    # different parameter -> different identity
    assert finding_hash(F(param="id")) != finding_hash(F(param="uid"))
    # different vuln class -> different identity
    assert finding_hash(F(vuln="sqli")) != finding_hash(F(vuln="xss"))


def test_dedupe_keeps_highest_confidence() -> None:
    res = dedupe_findings([F(conf="tentative"), F(conf="confirmed"), F(param="other")])
    assert len(res.unique) == 2       # two distinct identities
    assert res.duplicates == 1        # one collapsed
    kept = next(u for u in res.unique if u["parameter"] == "id")
    assert kept["confidence"] == "confirmed"  # highest-confidence instance survives


def test_reconcile_new_persistent_resolved() -> None:
    prev = [F(param="a"), F(param="b")]
    cur = [F(param="b"), F(param="c")]
    r = reconcile(prev, cur)
    assert r.summary == {"new": 1, "persistent": 1, "resolved": 1, "reappeared": 0}
    assert r.new[0]["parameter"] == "c"
    assert r.persistent[0]["parameter"] == "b"
    assert r.resolved[0]["parameter"] == "a"


def test_reconcile_flags_reappearance() -> None:
    cur = [F(param="x")]
    resolved_hash = finding_hash(F(param="x"))
    r = reconcile([], cur, previously_resolved=frozenset({resolved_hash}))
    assert len(r.reappeared) == 1
    assert r.summary["new"] == 1  # also counted as new (was absent last run)


def test_works_on_finding_objects_with_enums() -> None:
    def mk(param, conf):
        return Finding(
            vuln_type="sqli",
            title="t",
            severity=Severity.HIGH,
            confidence=conf,
            url="http://h/a?id=1",
            parameter=param,
            param_location=ParamLocation.QUERY,
            cwe="CWE-89",
            scanner="sqli",
            evidence=Evidence(),
        )

    res = dedupe_findings([mk("id", Confidence.TENTATIVE), mk("id", Confidence.CONFIRMED)])
    assert len(res.unique) == 1
    assert res.unique[0].confidence == Confidence.CONFIRMED
