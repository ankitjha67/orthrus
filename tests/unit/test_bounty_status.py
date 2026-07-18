"""One-view operator status aggregation."""

from __future__ import annotations

from orthrus.bounty.asset_monitor import AssetMonitor
from orthrus.bounty.audit import AuditLog
from orthrus.bounty.cost import CostLedger
from orthrus.bounty.history import HistoryStore
from orthrus.bounty.status import gather_status
from orthrus.bounty.store import ProgramRecord, ProgramStore
from orthrus.bounty.submissions import Submission, SubmissionStore
from orthrus.bounty.suppress import SuppressionStore, make_rule
from orthrus.core.schemas import Confidence, Finding, Severity


def test_gather_status_aggregates_all_stores(tmp_path, monkeypatch):
    monkeypatch.setenv("ORTHRUS_HOME", str(tmp_path))  # isolate all default stores

    ProgramStore().save(ProgramRecord(name="acme", authorization="direct:x", in_scope=["*.acme.com"]))
    SubmissionStore().add(Submission(program="acme", title="SQLi", status="rewarded", bounty_amount=500))
    HistoryStore().record([Finding(vuln_type="sqli", title="SQLi", severity=Severity.HIGH,
                                    confidence=Confidence.FIRM, url="https://a.acme.com/1")], "acme")
    AuditLog().append("bounty-campaign", "completed", {"program": "acme"})
    SuppressionStore().add("acme", make_rule(vuln_type="security-headers", reason="noise"))
    AssetMonitor().record("acme", ["a.acme.com", "b.acme.com"])
    CostLedger().record_llm("gpt-4o", "x" * 400, "y" * 400, provider="openai", program="acme")

    st = gather_status()
    assert [p["name"] for p in st["programs"]] == ["acme"]
    assert st["submissions"]["rewarded"] == 1
    assert st["submissions"]["earnings"] == {"USD": 500.0}
    assert st["history_signatures"] == 1
    assert st["audit"] == {"entries": 1, "intact": True, "first_bad": -1}
    assert st["mute_rules"] == 1 and st["programs"][0]["mute_rules"] == 1
    assert st["tracked_assets"] == 2 and st["programs"][0]["assets"] == 2
    assert st["cost"]["entries"] == 1 and st["cost"]["total_usd"] > 0


def test_gather_status_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("ORTHRUS_HOME", str(tmp_path))
    st = gather_status()
    assert st["programs"] == [] and st["history_signatures"] == 0
    assert st["submissions"]["total"] == 0 and st["audit"]["intact"] is True
    assert st["mute_rules"] == 0 and st["tracked_assets"] == 0 and st["cost"]["entries"] == 0
