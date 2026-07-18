"""Persisted bug-bounty programs (save / load / re-run)."""

from __future__ import annotations

from orthrus.bounty.store import ProgramRecord, ProgramStore


def test_record_round_trips_to_scope():
    rec = ProgramRecord(name="acme", authorization="https://hackerone.com/acme",
                        in_scope=["*.acme.com", "api.acme.com"], out_scope=["admin.acme.com"])
    ps = rec.to_scope()
    assert "acme.com" in ps.domains and "api.acme.com" in ps.domains
    assert ps.is_in_scope("www.acme.com") is True
    assert ps.is_in_scope("admin.acme.com") is False  # excluded survives the round-trip


def test_store_save_get_list_delete(tmp_path):
    store = ProgramStore(tmp_path / "programs.json")
    assert store.list() == []
    store.save(ProgramRecord(name="Acme", authorization="direct:letter", in_scope=["*.acme.com"]))
    store.save(ProgramRecord(name="beta", in_scope=["*.beta.com"]))
    got = store.get("acme")                       # case-insensitive key
    assert got is not None and got.authorization == "direct:letter"
    assert [r.name for r in store.list()] == ["Acme", "beta"]  # sorted
    assert store.delete("ACME") is True
    assert store.get("acme") is None and store.delete("acme") is False


def test_save_preserves_created_at_and_persists(tmp_path):
    path = tmp_path / "programs.json"
    ProgramStore(path).save(ProgramRecord(name="acme", in_scope=["*.acme.com"]))
    created = ProgramStore(path).get("acme").created_at   # a fresh store reads from disk
    ProgramStore(path).save(ProgramRecord(name="acme", in_scope=["*.acme.com", "new.acme.com"]))
    reloaded = ProgramStore(path).get("acme")
    assert reloaded.created_at == created                 # creation time preserved across updates
    assert "new.acme.com" in reloaded.in_scope


def test_record_run_tracks_history(tmp_path):
    store = ProgramStore(tmp_path / "programs.json")
    store.save(ProgramRecord(name="acme", in_scope=["*.acme.com"]))
    store.record_run("acme", ["bounty-1-01", "bounty-1-02"])
    store.record_run("acme", ["bounty-1-02", "bounty-2-01"])  # dedups
    rec = store.get("acme")
    assert rec.scan_ids == ["bounty-1-01", "bounty-1-02", "bounty-2-01"]
    assert rec.last_run_at is not None
    store.record_run("missing", ["x"])  # no-op, no crash
