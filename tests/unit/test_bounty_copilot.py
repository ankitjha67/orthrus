"""Data-grounded bounty copilot: retrieval + prompt building."""

from __future__ import annotations

from orthrus.bounty.copilot import Doc, build_prompt, rank, retrieve


def test_rank_orders_by_relevance_and_excludes_no_overlap():
    docs = [
        Doc("note:1", "Cloudflare WAF", "bypass cloudflare waf with json body and header casing"),
        Doc("note:2", "SQLi tips", "union based sql injection order by clause"),
        Doc("note:3", "misc", "random unrelated content about cats and gardening"),
    ]
    hits = rank("cloudflare waf json bypass", docs, k=3)
    assert hits and hits[0].source == "note:1"
    assert all(h.source != "note:3" for h in hits)   # zero term overlap -> not returned


def test_rank_handles_empty():
    assert rank("", [Doc("n:1", "t", "x")]) == []
    assert rank("anything", []) == []


def test_build_prompt_has_context_and_question():
    hits = rank("waf", [Doc("note:1", "Cloudflare WAF", "bypass the waf")], k=1)
    p = build_prompt("how do I bypass the waf", hits)
    assert "CONTEXT:" in p and "QUESTION: how do I bypass the waf" in p and "[note:1]" in p


def test_retrieve_over_real_notes(tmp_path, monkeypatch):
    monkeypatch.setenv("ORTHRUS_HOME", str(tmp_path))
    from orthrus.bounty.notes import Note, NotesStore

    NotesStore().add(Note(title="JWT jku attack", body="set the jku header to an attacker jwks url",
                          tags=["jwt", "auth"]))
    NotesStore().add(Note(title="XSS notes", body="use marker-namespaced globals", tags=["xss"]))

    hits = retrieve("jku jwt header", k=5)
    assert hits and hits[0].title == "JWT jku attack"
    assert retrieve("nonexistent-term-xyzzy") == []   # nothing relevant -> empty
