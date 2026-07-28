"""Tests for the pure session-fixation verdict logic."""

from __future__ import annotations

from orthrus.bounty.weakness import weakness_label
from orthrus.scanners.session_fixation import (
    accepts_forged_session,
    issued_session_cookies,
    looks_like_session_name,
    session_token_in_url,
)


def test_looks_like_session_name():
    for good in ("PHPSESSID", "JSESSIONID", "sessionid", "sid", "laravel_session", "my_session_id"):
        assert looks_like_session_name(good)
    for bad in ("csrftoken", "user", "auth", "theme", "q"):
        assert not looks_like_session_name(bad)


def test_session_token_in_url_path_matrix():
    hit = session_token_in_url("https://x.example/app;jsessionid=ABCD1234EFGH5678/home")
    assert hit is not None and hit[0].lower() == "jsessionid" and hit[1] == "path"


def test_session_token_in_url_query():
    hit = session_token_in_url("https://x.example/login?PHPSESSID=abcdef12345678")
    assert hit is not None and hit[0].lower() == "phpsessid" and hit[1] == "query"


def test_session_token_in_url_ignores_short_or_nonsession():
    assert session_token_in_url("https://x.example/p?session=abc") is None       # too short
    assert session_token_in_url("https://x.example/p?csrf=abcdefgh12345678") is None  # not a session
    assert session_token_in_url("https://x.example/p?q=hello+world") is None


def test_issued_session_cookies_filters_to_session_names():
    lines = ["PHPSESSID=abc123def456; Path=/; HttpOnly", "csrftoken=xyz; Path=/", "theme=dark"]
    assert issued_session_cookies(lines) == {"phpsessid": "abc123def456"}
    assert issued_session_cookies(["theme=dark"]) == {}


def test_accepts_forged_session_no_reissue_is_accepted():
    # Server did not re-issue the session cookie -> it kept our forged value.
    assert accepts_forged_session("PHPSESSID", "orthrusfxAAA", []) is True
    assert accepts_forged_session("PHPSESSID", "orthrusfxAAA", ["other=1; Path=/"]) is True


def test_accepts_forged_session_echo_is_accepted():
    assert accepts_forged_session("PHPSESSID", "orthrusfxAAA", ["PHPSESSID=orthrusfxAAA; Path=/"]) is True


def test_accepts_forged_session_regeneration_is_safe():
    # Server issued a fresh, different value -> regenerated -> not vulnerable.
    assert accepts_forged_session("PHPSESSID", "orthrusfxAAA", ["PHPSESSID=server_fresh_9f8e; Path=/"]) is False


def test_cwe_384_is_mapped_for_submission():
    assert weakness_label("CWE-384") == "Session Fixation (cwe-384)"
