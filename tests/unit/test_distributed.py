"""Tests for distributed target partitioning / loading (no broker needed)."""

from __future__ import annotations

from hydra.distributed.dispatcher import load_targets, partition_targets


def test_partition_round_robin():
    buckets = partition_targets(["a", "b", "c", "d", "e"], 2)
    assert len(buckets) == 2
    assert buckets[0] == ["a", "c", "e"]
    assert buckets[1] == ["b", "d"]


def test_partition_more_workers_than_targets():
    buckets = partition_targets(["a", "b"], 8)
    assert len(buckets) == 2  # never more buckets than targets
    assert sorted(t for b in buckets for t in b) == ["a", "b"]


def test_partition_empty():
    assert partition_targets([], 4) == [[]]


def test_load_targets_from_comma_list():
    assert load_targets("https://a.com, https://b.com ,https://c.com") == [
        "https://a.com",
        "https://b.com",
        "https://c.com",
    ]


def test_load_targets_from_file(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("https://a.com\n# comment\n\nhttps://b.com\n", encoding="utf-8")
    assert load_targets(str(f)) == ["https://a.com", "https://b.com"]
