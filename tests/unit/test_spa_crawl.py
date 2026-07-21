"""SPA route discovery recon: route resolution + the navigate/harvest flow.

The scanner drives a headless browser, so the tests substitute a duck-typed fake
browser that (a) returns declared client-side routes from ``evaluate_on`` and
(b) appends a route-specific captured XHR each time a route is ``render``ed -
exactly the contract ``orthrus.core.browser.BrowserManager`` exposes.
"""

from __future__ import annotations

from orthrus.core.browser import CapturedRequest
from orthrus.recon.spa_crawl import SpaCrawl, _resolve_route


# ----------------------------------------------------------- route resolution
def test_resolve_relative_and_absolute() -> None:
    base = "http://t.test/app"
    assert _resolve_route(base, "/orders/1") == "http://t.test/orders/1"
    assert _resolve_route(base, "products") == "http://t.test/products"
    assert _resolve_route(base, "http://t.test/admin") == "http://t.test/admin"


def test_resolve_keeps_hash_route() -> None:
    # Hash-based routers keep the fragment - it *is* the client-side route.
    assert _resolve_route("http://t.test/", "#/administration") == "http://t.test/#/administration"


def test_resolve_rejects_non_navigable() -> None:
    base = "http://t.test/"
    assert _resolve_route(base, "javascript:void(0)") is None
    assert _resolve_route(base, "mailto:a@b.test") is None
    assert _resolve_route(base, "#") is None
    assert _resolve_route(base, "") is None
    assert _resolve_route(base, "tel:+15551234") is None


# ----------------------------------------------------------- navigate/harvest
class _Scope:
    def is_allowed(self, url: str) -> bool:
        return "evil.test" not in url


class _FakeBrowser:
    """Returns declared routes, and fires a route-specific XHR on each render."""

    def __init__(self, routes: list[str]) -> None:
        self._routes = routes
        self.captured: list[CapturedRequest] = []
        self.navigated: list[str] = []

    async def evaluate_on(self, url: str, expression: str, *, wait_ms: int = 0) -> list[str]:
        return list(self._routes)

    async def render(self, url: str, *, wait_ms: int = 0) -> str:
        self.navigated.append(url)
        if "administration" in url:
            self.captured.append(
                CapturedRequest(method="GET", url="http://t.test/rest/admin/users",
                                resource_type="xhr")
            )
        elif "orders" in url:
            self.captured.append(
                CapturedRequest(method="GET", url="http://t.test/rest/orders?page=1",
                                resource_type="xhr")
            )
        return "<html></html>"


class _Config:
    target = "http://t.test/"


class _Ctx:
    def __init__(self, browser) -> None:
        self.config = _Config()
        self.endpoints: list = []
        self.scope = _Scope()
        self.browser = browser


def test_applicable_requires_browser() -> None:
    assert SpaCrawl().applicable(_Ctx(_FakeBrowser([]))) is True
    assert SpaCrawl().applicable(_Ctx(None)) is False


async def test_navigates_routes_and_harvests_new_endpoints() -> None:
    browser = _FakeBrowser(
        [
            "#/administration",          # hash route -> /rest/admin/users
            "/orders/42",                # history route -> /rest/orders
            "http://evil.test/pwn",      # out of scope, must be skipped
            "javascript:void(0)",        # not navigable
            "/",                         # bare shell, already crawled -> skipped
        ]
    )
    ctx = _Ctx(browser)
    eps = [ep async for ep in SpaCrawl().discover(ctx)]

    # Out-of-scope + non-navigable + shell routes were never driven.
    assert "http://evil.test/pwn" not in browser.navigated
    assert browser.navigated == ["http://t.test/#/administration", "http://t.test/orders/42"]

    urls = sorted(ep.url for ep in eps)
    assert urls == ["http://t.test/rest/admin/users", "http://t.test/rest/orders?page=1"]
    assert all(ep.source == "spa-routes" for ep in eps)


async def test_only_emits_captures_from_its_own_navigation() -> None:
    # A pre-existing capture (e.g. from browser-crawl) must not be re-emitted.
    browser = _FakeBrowser(["/orders/1"])
    browser.captured.append(
        CapturedRequest(method="GET", url="http://t.test/rest/preexisting", resource_type="xhr")
    )
    ctx = _Ctx(browser)
    eps = [ep async for ep in SpaCrawl().discover(ctx)]
    urls = [ep.url for ep in eps]
    assert "http://t.test/rest/preexisting" not in urls
    assert urls == ["http://t.test/rest/orders?page=1"]


async def test_no_routes_yields_nothing() -> None:
    browser = _FakeBrowser([])
    eps = [ep async for ep in SpaCrawl().discover(_Ctx(browser))]
    assert eps == []
    assert browser.navigated == []
