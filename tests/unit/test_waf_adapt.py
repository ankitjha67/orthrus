"""Adaptive WAF resilience in the HTTP client: identity rotation + block-retry.

Like the reauth tests, these drive a bare ``HttpClient`` whose ``_send`` is
stubbed, so we exercise the ``request()`` orchestration (block detection ->
identity rotation -> single retry) without real sockets.
"""

from __future__ import annotations

from orthrus.core.auth import DEFAULT_REAUTH_MARKERS
from orthrus.core.block_detect import BlockMonitor
from orthrus.core.http_client import USER_AGENTS, HttpClient
from orthrus.core.session import Session


class FakeResp:
    def __init__(self, status: int, *, text: str = "", headers: dict | None = None) -> None:
        self.status_code = status
        self.text = text
        self.headers = headers or {}


def _bare_client(*, waf_adapt: bool = True) -> HttpClient:
    client = HttpClient.__new__(HttpClient)
    client.session = Session()
    client._reauthing = False
    client.reauth_markers = DEFAULT_REAUTH_MARKERS
    client.block_monitor = BlockMonitor()
    client.waf_adapt = waf_adapt
    client._evading = False
    client._last_ua = None
    client.block_backoff = (0.0, 0.0)  # no cool-off sleep in tests
    client.event_bus = None
    return client


_BLOCKED = FakeResp(403, text="Just a moment... challenge-platform",
                    headers={"Server": "cloudflare", "cf-ray": "x"})
_CLEAN = FakeResp(200, text="ok", headers={"Server": "nginx"})


async def test_block_triggers_one_retry_with_rotated_identity() -> None:
    client = _bare_client()
    responses = [_BLOCKED, _CLEAN]
    sent: list[dict] = []

    async def fake_send(method, url, *, follow_redirects=True, headers=None, **kwargs):
        sent.append({"headers": headers})
        return responses[len(sent) - 1]

    client._send = fake_send  # type: ignore[method-assign,assignment]
    resp = await client.request("GET", "http://t.test/x")

    assert resp.status_code == 200
    assert len(sent) == 2  # original + one evasion retry
    # The retry carried a rotated browser identity (the original had none injected).
    retry_ua = sent[1]["headers"]["User-Agent"]
    assert retry_ua in USER_AGENTS
    # Monitor saw one block then one clean response.
    assert client.block_monitor.total == 2
    assert client.block_monitor.blocked == 1
    assert client.block_monitor.vendors == {"Cloudflare"}


async def test_no_retry_when_waf_adapt_disabled() -> None:
    client = _bare_client(waf_adapt=False)
    sent: list[str] = []

    async def fake_send(method, url, *, follow_redirects=True, headers=None, **kwargs):
        sent.append(url)
        return _BLOCKED

    client._send = fake_send  # type: ignore[method-assign,assignment]
    resp = await client.request("GET", "http://t.test/x")

    assert resp.status_code == 403
    assert len(sent) == 1  # block recorded, but no retry
    assert client.block_monitor.blocked == 1


async def test_persistent_block_returns_after_single_retry() -> None:
    client = _bare_client()
    sent: list[str] = []

    async def fake_send(method, url, *, follow_redirects=True, headers=None, **kwargs):
        sent.append(url)
        return _BLOCKED  # still blocked even after rotation

    client._send = fake_send  # type: ignore[method-assign,assignment]
    resp = await client.request("GET", "http://t.test/x")

    assert resp.status_code == 403
    assert len(sent) == 2  # exactly one retry, no infinite loop
    assert client.block_monitor.total == 2
    assert client.block_monitor.blocked == 2


async def test_rate_limit_is_recorded_but_not_retried() -> None:
    # A 429 is left to the rate limiter's backoff — no immediate identity-rotation
    # retry (which would only add load to an already-throttled host).
    client = _bare_client()
    sent: list[str] = []

    async def fake_send(method, url, *, follow_redirects=True, headers=None, **kwargs):
        sent.append(url)
        return FakeResp(429, text="slow down", headers={"Retry-After": "1"})

    client._send = fake_send  # type: ignore[method-assign,assignment]
    resp = await client.request("GET", "http://t.test/x")
    assert resp.status_code == 429
    assert len(sent) == 1  # recorded, not retried
    assert client.block_monitor.blocked == 1


async def test_clean_response_never_retries() -> None:
    client = _bare_client()
    sent: list[str] = []

    async def fake_send(method, url, *, follow_redirects=True, headers=None, **kwargs):
        sent.append(url)
        return _CLEAN

    client._send = fake_send  # type: ignore[method-assign,assignment]
    resp = await client.request("GET", "http://t.test/x")
    assert resp.status_code == 200
    assert len(sent) == 1
    assert client.block_monitor.blocked == 0


# ------------------------------------------------------------- header identity
def test_browser_headers_chrome_vs_firefox() -> None:
    chrome = next(ua for ua in USER_AGENTS if "Chrome/" in ua and "Firefox" not in ua)
    firefox = next(ua for ua in USER_AGENTS if "Firefox/" in ua)
    ch = HttpClient._browser_headers(chrome)
    ff = HttpClient._browser_headers(firefox)
    assert "Accept" in ch and "Accept-Language" in ch
    # Chromium advertises client hints + fetch metadata; Firefox does not.
    assert "sec-ch-ua" in ch and ch["Sec-Fetch-Dest"] == "document"
    assert "sec-ch-ua" not in ff


def test_merge_headers_sets_browser_defaults_and_ua() -> None:
    client = HttpClient.__new__(HttpClient)
    client.session = Session()
    client.extra_headers = {}
    client.user_agent = "random"
    client._last_ua = None
    merged = client._merge_headers({"X-Test": "1"})
    assert merged["Accept"].startswith("text/html")
    assert merged["User-Agent"] in USER_AGENTS
    assert merged["X-Test"] == "1"  # caller header preserved


def test_rotate_user_agent_avoids_repeat() -> None:
    client = HttpClient.__new__(HttpClient)
    # A rotation never returns the UA that was last used (reset each time so the
    # exclusion target stays fixed across trials).
    for _ in range(20):
        client._last_ua = USER_AGENTS[0]
        assert client._rotate_user_agent() != USER_AGENTS[0]
