"""Known-pattern novelty gate."""

from __future__ import annotations

from orthrus.risk.novelty import (
    LOW,
    MEDIUM,
    NOVEL,
    assess_novelty,
    partition_by_novelty,
)


def F(vuln_type="xss", title="", description=""):
    return {"vuln_type": vuln_type, "title": title, "description": description}


def test_low_novelty_by_class() -> None:
    v = assess_novelty(F(vuln_type="clickjacking", title="Clickjacking on /login"))
    assert v.novelty == LOW and v.matched is not None


def test_low_novelty_by_keyword_any_class() -> None:
    v = assess_novelty(F(vuln_type="headers", title="Missing X-Frame-Options header"))
    assert v.novelty == LOW


def test_medium_novelty_git_exposure() -> None:
    v = assess_novelty(F(vuln_type="exposed-files", title="Exposed .git directory"))
    assert v.novelty == MEDIUM


def test_novel_when_no_pattern_matches() -> None:
    v = assess_novelty(F(vuln_type="sqli", title="Blind SQL injection in checkout coupon"))
    assert v.novelty == NOVEL and v.matched is None


def test_lowest_novelty_wins_on_multiple_matches() -> None:
    # Title mentions both a low (.env is medium) and a low header pattern -> LOW wins.
    v = assess_novelty(F(vuln_type="headers", title="Missing content-security-policy and .env exposed"))
    assert v.novelty == LOW


def test_partition_orders_triage() -> None:
    findings = [
        F(vuln_type="sqli", title="Second-order SQLi via stored profile"),   # novel
        F(vuln_type="clickjacking", title="Clickjacking"),                    # low
        F(vuln_type="exposed-files", title=".env exposed"),                   # medium
    ]
    buckets = partition_by_novelty(findings)
    assert len(buckets[NOVEL]) == 1
    assert len(buckets[LOW]) == 1
    assert len(buckets[MEDIUM]) == 1
