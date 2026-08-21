"""Cross-run memory ledger (skip decisions, rollup, persistence)."""

from __future__ import annotations

from orthrus.risk.memory_ledger import (
    DEAD_CLASS_THRESHOLD,
    FindingRecord,
    MemoryLedger,
    load_ledger,
    rollup,
    save_ledger,
    skip_decision,
    tech_stack_signature,
)


def test_tech_stack_signature_is_deterministic() -> None:
    assert tech_stack_signature(["Nginx", "PHP", "nginx"]) == "nginx|php"
    assert tech_stack_signature(["PHP", "Nginx"]) == "nginx|php"  # order-independent
    assert tech_stack_signature([]) == ""


def test_record_finding_dedupes_and_upgrades_to_confirmed() -> None:
    led = MemoryLedger()
    led.record_finding(FindingRecord("h", "/a", "id", "idor", confirmed=False))
    led.record_finding(FindingRecord("h", "/a", "id", "idor", confirmed=True))  # upgrade
    led.record_finding(FindingRecord("h", "/a", "id", "idor", confirmed=False))  # no downgrade
    assert len(led.findings) == 1
    assert led.findings[0].confirmed is True


def test_skip_known_confirmed() -> None:
    led = MemoryLedger()
    led.record_finding(FindingRecord("h", "/a", "id", "idor", confirmed=True, tech_sig="php"))
    d = skip_decision(led, "h", "/a", "id", "idor", "php")
    assert d.skip is True and d.reason == "known-confirmed"


def test_skip_dead_class_after_threshold() -> None:
    led = MemoryLedger()
    for _ in range(DEAD_CLASS_THRESHOLD):
        led.record_negative("php|nginx", "xxe")
    # dead class on that stack -> skip, and it transfers to a different host on the same stack
    d = skip_decision(led, "other-host", "/x", "p", "xxe", "php|nginx")
    assert d.skip is True and d.reason == "dead-class"
    # a different class on the same stack is not skipped
    assert skip_decision(led, "h", "/x", "p", "sqli", "php|nginx").skip is False


def test_dead_class_not_triggered_when_class_confirmed_on_stack() -> None:
    led = MemoryLedger()
    for _ in range(DEAD_CLASS_THRESHOLD + 2):
        led.record_negative("php", "sqli")
    led.record_finding(FindingRecord("h1", "/a", "q", "sqli", confirmed=True, tech_sig="php"))
    # confirmed at least once on this stack -> never skip it as dead
    assert skip_decision(led, "h2", "/b", "q", "sqli", "php").skip is False


def test_below_threshold_is_not_skipped() -> None:
    led = MemoryLedger()
    for _ in range(DEAD_CLASS_THRESHOLD - 1):
        led.record_negative("php", "ssrf")
    assert skip_decision(led, "h", "/a", "p", "ssrf", "php").skip is False


def test_rollup() -> None:
    led = MemoryLedger()
    led.record_finding(FindingRecord("h", "/a", "id", "idor", confirmed=True, scan_id="s1"))
    led.record_finding(FindingRecord("h", "/b", "q", "sqli", confirmed=False, scan_id="s2"))
    r = rollup(led, "h")
    assert r["findings"] == 2 and r["confirmed"] == 1
    assert r["classes_confirmed"] == ["idor"]
    assert r["last_scan"] == "s2"


def test_persistence_round_trip(tmp_path) -> None:
    led = MemoryLedger()
    led.record_finding(FindingRecord("h", "/a", "id", "idor", confirmed=True, tech_sig="php", scan_id="s1"))
    led.record_negative("php", "xxe", count=3)
    save_ledger(led, tmp_path)

    loaded = load_ledger(tmp_path)
    assert len(loaded.findings) == 1
    assert loaded.findings[0].confirmed is True
    assert loaded.negatives[("php", "xxe")] == 3
    # skip decisions reproduce from the reloaded ledger
    assert skip_decision(loaded, "h", "/a", "id", "idor", "php").reason == "known-confirmed"


def test_load_missing_dir_is_empty(tmp_path) -> None:
    led = load_ledger(tmp_path / "does-not-exist")
    assert led.findings == [] and led.negatives == {}
