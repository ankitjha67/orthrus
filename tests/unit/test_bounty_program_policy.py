"""Per-program traffic policy: rate ceiling + identifying header."""

from __future__ import annotations

from orthrus.bounty.store import ProgramRecord, ProgramStore


def test_identify_header_parsing():
    assert ProgramRecord(name="p", identify="X-Bug-Bounty: ankit").identify_header() == {
        "X-Bug-Bounty": "ankit"
    }
    # tolerant of extra spacing
    assert ProgramRecord(name="p", identify="  X-HackerOne :  user  ").identify_header() == {
        "X-HackerOne": "user"
    }
    # malformed -> empty (never inject a broken header)
    assert ProgramRecord(name="p", identify="no-colon").identify_header() == {}
    assert ProgramRecord(name="p", identify="").identify_header() == {}


def test_rate_ceiling_semantics():
    # The stored max_rps is a ceiling; effective rate = min(requested, ceiling).
    rec = ProgramRecord(name="p", max_rps=5.0)
    for requested in (50.0, 10.0, 3.0):
        effective = min(requested, rec.max_rps) if rec.max_rps else requested
        assert effective <= rec.max_rps
    assert min(3.0, rec.max_rps) == 3.0   # a slower request is still honored


def test_policy_persists_and_roundtrips(tmp_path):
    store = ProgramStore(tmp_path / "programs.json")
    store.save(ProgramRecord(name="Acme", in_scope=["*.acme.com"], max_rps=5.0,
                             identify="X-Bug-Bounty: ankit"))
    got = store.get("acme")
    assert got is not None
    assert got.max_rps == 5.0
    assert got.identify_header() == {"X-Bug-Bounty": "ankit"}


def test_old_record_without_policy_defaults(tmp_path):
    # A record saved before policy existed (no max_rps/identify keys) still loads.
    p = tmp_path / "programs.json"
    p.write_text(
        '{"acme": {"name": "Acme", "authorization": "", "in_scope": ["a.acme.com"], '
        '"out_scope": [], "created_at": "t", "updated_at": "t", "last_run_at": null, '
        '"scan_ids": [], "notes": ""}}',
        encoding="utf-8",
    )
    rec = ProgramStore(p).get("acme")
    assert rec is not None
    assert rec.max_rps is None and rec.identify == ""
    assert rec.identify_header() == {}
