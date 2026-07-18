"""Tamper-evident bug-bounty audit log."""

from __future__ import annotations

from orthrus.bounty.audit import AuditLog


def test_empty_log_verifies(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    assert log.entries() == []
    assert log.verify() == (True, -1)


def test_append_chains_and_verifies(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    a = log.append("bounty-campaign", "completed", {"program": "acme", "reportable": 3})
    b = log.append("bounty-refused", "kill-list-block", {"hosts": ["x.gov"]})
    assert a["prev_hash"] == "genesis"
    assert b["prev_hash"] == a["row_hash"]          # chained to the previous entry
    assert log.verify() == (True, -1)
    assert len(log.entries()) == 2


def test_verify_detects_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("bounty-campaign", "completed", {"program": "acme", "reportable": 1})
    log.append("bounty-campaign", "completed", {"program": "acme", "reportable": 2})
    # tamper with the first entry's details on disk
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace('"reportable": 1', '"reportable": 99')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, bad = AuditLog(path).verify()
    assert ok is False and bad == 0                 # tampering flagged at the edited row


def test_verify_detects_deletion(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("a", "x")
    log.append("b", "y")
    log.append("c", "z")
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(lines[0] + "\n" + lines[2] + "\n", encoding="utf-8")  # drop the middle entry
    ok, _ = AuditLog(path).verify()
    assert ok is False                              # broken chain after a deletion
