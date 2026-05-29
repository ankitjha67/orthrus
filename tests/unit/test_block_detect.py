"""WAF/anti-automation block detection: the per-response classifier + monitor.

The classifier must flag genuine WAF interference (rate-limits, JS/CAPTCHA
interstitials, vendor block pages) while leaving ordinary application responses
— including a plain app 403 — untouched, so it never inflates the block rate.
"""

from __future__ import annotations

from orthrus.core.block_detect import BlockMonitor, BlockVerdict, detect_block


# --------------------------------------------------------------- positive cases
def test_429_is_always_a_block() -> None:
    v = detect_block(429, {}, "")
    assert v and v.blocked and not v.challenge
    assert "rate-limited" in v.reason


def test_cloudflare_js_challenge() -> None:
    v = detect_block(403, {"Server": "cloudflare", "CF-RAY": "abc"},
                     "<title>Just a moment...</title> challenge-platform")
    assert v and v.blocked and v.challenge
    assert v.vendor == "Cloudflare"


def test_cf_mitigated_header_is_a_challenge() -> None:
    v = detect_block(403, {"cf-mitigated": "challenge", "cf-ray": "x"}, "")
    assert v and v.blocked and v.challenge and v.vendor == "Cloudflare"


def test_incapsula_hard_block() -> None:
    v = detect_block(403, {"X-Iinfo": "1-2-3"},
                     "Request unsuccessful. Incapsula incident ID: 999")
    assert v and v.blocked and not v.challenge
    assert v.vendor == "Imperva Incapsula"


def test_akamai_access_denied_reference() -> None:
    v = detect_block(403, {"Server": "AkamaiGHost"},
                     "Access Denied\nReference #18.abcd")
    assert v and v.blocked
    assert v.vendor == "Akamai"


def test_captcha_page_with_200_status() -> None:
    # Some WAFs serve the interstitial with a 200 — body is the giveaway.
    v = detect_block(200, {}, "Please complete the security check to continue. hCaptcha")
    assert v and v.blocked and v.challenge


# --------------------------------------------------------------- negative cases
def test_plain_app_403_is_not_a_block() -> None:
    assert detect_block(403, {"Server": "nginx"}, "Forbidden: you lack permission") is None


def test_normal_200_behind_cloudflare_is_not_a_block() -> None:
    # cf-ray present (fronted by Cloudflare) but a genuine page -> not blocked.
    assert detect_block(200, {"cf-ray": "abc", "Server": "cloudflare"},
                        "<html>welcome to the dashboard</html>") is None


def test_503_without_challenge_is_not_a_block() -> None:
    # A bare 503 could be real overload; don't classify without a WAF signature.
    assert detect_block(503, {"Server": "nginx"}, "Service Unavailable") is None


def test_404_is_not_a_block() -> None:
    assert detect_block(404, {}, "Not Found") is None


# --------------------------------------------------------------------- monitor
def test_monitor_tracks_rate_and_vendors() -> None:
    m = BlockMonitor()
    blocked = BlockVerdict(True, "Cloudflare", "x", challenge=True)
    m.record("a.test", None)
    m.record("a.test", blocked)
    m.record("b.test", BlockVerdict(True, None, "y"))
    assert m.total == 3
    assert m.blocked == 2
    assert m.challenges == 1
    assert m.vendors == {"Cloudflare"}
    assert m.block_rate("a.test") == 0.5
    assert round(m.block_rate(), 3) == round(2 / 3, 3)


def test_monitor_degraded_needs_enough_requests() -> None:
    m = BlockMonitor()
    blocked = BlockVerdict(True, None, "x")
    # 3/3 blocked but below the min-requests floor -> not yet "degraded".
    for _ in range(3):
        m.record("h", blocked)
    assert not m.degraded()
    # Push past the floor with a high block rate.
    for _ in range(7):
        m.record("h", blocked)
    assert m.degraded()
    assert m.summary()["block_rate"] == 1.0
