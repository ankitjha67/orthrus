"""Cross-run history recall for bounty findings."""

from __future__ import annotations

from orthrus.bounty.history import HistoryStore, signature
from orthrus.core.schemas import Confidence, Finding, Severity


def _f(vt, title, url="https://a.example.com/x"):
    return Finding(vuln_type=vt, title=title, severity=Severity.HIGH,
                   confidence=Confidence.FIRM, url=url)


def test_signature_is_host_and_class_specific():
    a = _f("sqli", "SQL injection via id", "https://a.example.com/1")
    b = _f("sqli", "SQL injection via name", "https://a.example.com/2")  # same class+host (title normalizes)
    c = _f("sqli", "SQL injection", "https://b.example.com/1")           # different host
    assert signature(a) == signature(b)
    assert signature(a) != signature(c)


def test_record_reports_prior_seen(tmp_path):
    store = HistoryStore(tmp_path / "h.json")
    first = [_f("sqli", "SQL injection", "https://a.example.com/1"),
             _f("xss", "Reflected XSS", "https://a.example.com/2")]
    assert store.record(first, "acme") == 0            # nothing known yet

    second = [_f("sqli", "SQL injection", "https://a.example.com/1"),   # seen before
              _f("idor", "IDOR", "https://a.example.com/3")]           # new
    assert store.record(second, "acme") == 1           # exactly the SQLi was known

    entry = store.seen_before(_f("sqli", "SQL injection", "https://a.example.com/1"))
    assert entry is not None and entry["count"] == 2
    assert store.seen_before(_f("ssrf", "SSRF", "https://z.example.com/")) is None


def test_history_tracks_programs(tmp_path):
    store = HistoryStore(tmp_path / "h.json")
    bug = _f("sqli", "SQL injection", "https://a.example.com/1")
    store.record([bug], "acme")
    store.record([bug], "beta")                        # same bug, different program
    entry = store.seen_before(bug)
    assert set(entry["programs"]) == {"acme", "beta"} and entry["count"] == 2
