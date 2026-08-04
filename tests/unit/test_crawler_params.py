"""The crawler must surface ?param= GET links - including SPA filter links that
live in inline JS rather than <a href> anchors - as endpoints that carry their
query parameters, otherwise an injection scanner has nothing to test.

This is the ginandjuice /catalog?category= regression: the category filter links
are a React `{"Gin":"/catalog?category=Gin"}` map inside an inline <script>, so
they are invisible to anchor extraction and previously reached no scanner.
"""

from __future__ import annotations

import asyncio
import types

import httpx

from orthrus.core.config import ScopeConfig
from orthrus.core.schemas import ParamLocation
from orthrus.recon.crawler import Crawler
from orthrus.utils.scope import ScopeValidator

# Mirrors the real ginandjuice /catalog page: category links in inline JS, and a
# product link as a plain query-bearing anchor.
CATALOG_HTML = """
<html><body>
  <label>search:</label>
  <script type="text/javascript">
    const element = React.createElement;
    const categories = {"All":"/catalog","Accessories":"/catalog?category=Accessories",
      "Books":"/catalog?category=Books","Gin":"/catalog?category=Gin",
      "Juice":"/catalog?category=Juice"};
  </script>
  <a href="/catalog/product?productId=1">Product 1</a>
</body></html>
"""


class _Resp:
    def __init__(self, text="", status=200, ctype="text/html"):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.headers = httpx.Headers({"content-type": ctype})


class _FakeHttp:
    def __init__(self, routes):
        self.routes = routes

    async def get(self, url, follow_redirects=False):
        return self.routes.get(url, _Resp("not found", status=404))


def _ctx(routes, target, *, crawl_depth=10, max_pages=50):
    return types.SimpleNamespace(
        config=types.SimpleNamespace(
            target=target, crawl_depth=crawl_depth, max_pages=max_pages
        ),
        scope=ScopeValidator(ScopeConfig(domains=["shop.test"], ports=[])),
        http=_FakeHttp(routes),
        websockets=[],
    )


def _crawl(ctx):
    async def run():
        return [ep async for ep in Crawler().discover(ctx)]

    return asyncio.run(run())


def test_spa_category_filter_becomes_injection_point():
    target = "http://shop.test/catalog"
    eps = _crawl(_ctx({target: _Resp(CATALOG_HTML)}, target))

    cat_eps = [e for e in eps if any(p.name == "category" for p in e.params)]
    assert cat_eps, "JS-embedded ?category= filter link was not surfaced as an endpoint"
    # The five category values collapse to a single injection point.
    assert len(cat_eps) == 1
    ep = cat_eps[0]
    param = next(p for p in ep.params if p.name == "category")
    assert param.location is ParamLocation.QUERY
    assert ep.source == "js-inline"


def test_query_anchor_at_depth_frontier_is_harvested():
    # crawl_depth=0 makes the start page the frontier: its query-bearing anchor
    # can no longer be crawled, but the parameter must still be harvested.
    target = "http://shop.test/catalog"
    eps = _crawl(_ctx({target: _Resp(CATALOG_HTML)}, target, crawl_depth=0))

    harvested = [
        e
        for e in eps
        if e.source == "crawler-link" and any(p.name == "productId" for p in e.params)
    ]
    assert harvested, "query-bearing anchor at the depth frontier was dropped"


def test_query_anchor_is_crawled_and_carries_params_when_depth_allows():
    # With depth budget, the anchor is fetched and the fetched endpoint itself
    # carries the productId param (the harvest path is not the only route).
    target = "http://shop.test/catalog"
    product = "http://shop.test/catalog/product?productId=1"
    routes = {target: _Resp(CATALOG_HTML), product: _Resp("<html>a product</html>")}
    eps = _crawl(_ctx(routes, target, crawl_depth=3))

    pid = [e for e in eps if any(p.name == "productId" for p in e.params)]
    assert pid, "productId query link never became an injection point"
    assert any(e.url == product for e in pid)
