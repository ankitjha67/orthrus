"""Bug-bounty submission & payout tracking."""

from __future__ import annotations

from orthrus.bounty.submissions import Submission, SubmissionStore


def test_add_get_update(tmp_path):
    store = SubmissionStore(tmp_path / "s.json")
    sub = store.add(Submission(program="acme", title="SQL injection", platform="hackerone",
                               severity="high", status="filed"))
    assert store.get(sub.id).title == "SQL injection"
    updated = store.update(sub.id, status="rewarded", bounty_amount=1500.0)
    assert updated.status == "rewarded" and updated.bounty_amount == 1500.0
    assert updated.updated_at >= updated.created_at
    assert store.update("nope", status="closed") is None       # unknown id


def test_list_filter_and_summary(tmp_path):
    store = SubmissionStore(tmp_path / "s.json")
    store.add(Submission(program="acme", title="a", status="rewarded", bounty_amount=500, currency="USD"))
    store.add(Submission(program="acme", title="b", status="rewarded", bounty_amount=250, currency="USD"))
    store.add(Submission(program="acme", title="c", status="duplicate"))
    store.add(Submission(program="beta", title="d", status="rewarded", bounty_amount=100, currency="EUR"))

    assert len(store.list("acme")) == 3
    assert len(store.list()) == 4

    summ = store.summary("acme")
    assert summ["total"] == 3
    assert summ["rewarded"] == 2
    assert summ["earnings"] == {"USD": 750.0}                   # only acme's USD payouts
    assert summ["by_status"] == {"rewarded": 2, "duplicate": 1}

    assert store.summary()["earnings"] == {"USD": 750.0, "EUR": 100.0}  # all programs


def test_ids_are_unique(tmp_path):
    store = SubmissionStore(tmp_path / "s.json")
    a = store.add(Submission(program="p", title="x"))
    b = store.add(Submission(program="p", title="y"))
    assert a.id != b.id and len(store.list()) == 2
