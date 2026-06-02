"""Race-condition scanner: status parsing + limit-overrun oracle + candidates."""

from __future__ import annotations

from orthrus.scanners.race_condition import (
    build_raw_request,
    classify_race,
    is_race_candidate,
    parse_status,
)


def _resp(status: int) -> bytes:
    return f"HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n".encode()


def test_parse_status():
    assert parse_status(b"HTTP/1.1 200 OK\r\n\r\n") == 200
    assert parse_status(b"HTTP/1.1 409 Conflict\r\n\r\n") == 409
    assert parse_status(b"garbage") is None
    assert parse_status(b"") is None


def test_classify_race_flags_partial_overrun():
    # 3 accepted past a limit that rejected the other 17 → non-atomic overrun
    responses = [_resp(200)] * 3 + [_resp(409)] * 17
    v = classify_race(responses)
    assert v.raced and v.accepts == 3 and v.rejects == 17


def test_classify_race_atomic_endpoint_not_flagged():
    # exactly one accept, rest limit-rejected → correctly held → NOT a race
    responses = [_resp(200)] + [_resp(409)] * 19
    v = classify_race(responses)
    assert not v.raced and v.accepts == 1


def test_classify_race_unlimited_endpoint_not_flagged():
    # all accepted, no limit-rejections → unlimited endpoint, not a limit overrun
    responses = [_resp(200)] * 20
    assert not classify_race(responses).raced


def test_classify_race_rate_limiting_excluded():
    # 1 accept + 429s is benign throttling, not a check-then-commit race
    responses = [_resp(200)] + [_resp(429)] * 19
    v = classify_race(responses)
    assert not v.raced and v.rejects == 0  # 429 is not a limit-reject


def test_classify_race_needs_two_accepts():
    # a single accept among limit-rejects is the atomic (safe) outcome
    responses = [_resp(200)] + [_resp(403)] * 19
    assert not classify_race(responses).raced


def test_is_race_candidate():
    assert is_race_candidate("POST", "http://x/api/redeem")
    assert is_race_candidate("GET", "http://x/coupon/ABC")   # keyword path
    assert is_race_candidate("DELETE", "http://x/item/1")
    assert not is_race_candidate("GET", "http://x/about")     # read-only, no keyword


def test_build_raw_request_with_and_without_body():
    raw = build_raw_request("POST", "host.test", "/redeem", "code=ABC")
    assert raw.startswith(b"POST /redeem HTTP/1.1\r\n")
    assert b"Host: host.test\r\n" in raw
    assert b"Content-Length: 8\r\n" in raw
    assert raw.endswith(b"code=ABC")
    # GET with no body has no Content-Length and ends with the blank line
    g = build_raw_request("GET", "host.test", "/coupon", "")
    assert b"Content-Length" not in g and g.endswith(b"\r\n\r\n")
