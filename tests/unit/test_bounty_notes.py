"""Operator notes store: save / filter / search."""

from __future__ import annotations

from orthrus.bounty.notes import Note, NotesStore


def test_add_get_delete(tmp_path):
    store = NotesStore(tmp_path / "n.json")
    n = store.add(Note(title="Cloudflare WAF bypass", body="try json body + header casing",
                       program="acme", tags=["waf", "cloudflare"]))
    assert store.get(n.id).title == "Cloudflare WAF bypass"
    assert store.delete(n.id) is True and store.get(n.id) is None
    assert store.delete(n.id) is False


def test_list_filters_by_program_and_tag(tmp_path):
    store = NotesStore(tmp_path / "n.json")
    store.add(Note(title="a", program="acme", tags=["recon"]))
    store.add(Note(title="b", program="acme", tags=["xss"]))
    store.add(Note(title="c", program="beta", tags=["recon"]))
    assert {n.title for n in store.list(program="acme")} == {"a", "b"}
    assert {n.title for n in store.list(tag="recon")} == {"a", "c"}
    assert {n.title for n in store.list(program="acme", tag="recon")} == {"a"}


def test_search_matches_body_and_tags(tmp_path):
    store = NotesStore(tmp_path / "n.json")
    store.add(Note(title="JWT tips", body="check alg=none and jku header", tags=["auth"]))
    store.add(Note(title="XSS payloads", body="use marker-namespaced globals", tags=["xss"]))
    assert {n.title for n in store.search("jku")} == {"JWT tips"}          # body hit
    assert {n.title for n in store.search("auth")} == {"JWT tips"}         # tag hit
    assert {n.title for n in store.search("payloads")} == {"XSS payloads"}  # title hit
    assert len(store.search("")) == 2                                      # empty query -> all
