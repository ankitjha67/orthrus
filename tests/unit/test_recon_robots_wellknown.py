"""Recon: robots.txt + sitemap and /.well-known/ endpoint discovery."""

from __future__ import annotations

import asyncio
import gzip
import types

from orthrus.core.config import ScopeConfig
from orthrus.recon.robots_sitemap import (
    RobotsSitemap,
    _decode_sitemap,
    parse_robots,
    parse_sitemap,
)
from orthrus.recon.well_known import (
    WellKnown,
    parse_openid_config,
    parse_security_txt,
)
from orthrus.utils.scope import ScopeValidator

# --- pure parsers --------------------------------------------------------

def test_parse_robots_paths_and_sitemaps():
    text = (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /internal/export\n"
        "Allow: /public\n"
        "Disallow: /*.json$\n"   # wildcard — skipped (not directly requestable)
        "Disallow: /\n"          # site-wide — skipped
        "# comment\n"
        "Sitemap: https://t/sitemap.xml\n"
    )
    paths, sitemaps = parse_robots(text)
    assert paths == ["/admin/", "/internal/export", "/public"]
    assert sitemaps == ["https://t/sitemap.xml"]


def test_parse_sitemap_urlset_and_index():
    urlset = "<urlset><url><loc>https://t/a</loc></url><url><loc>https://t/b</loc></url></urlset>"
    locs, is_index = parse_sitemap(urlset)
    assert locs == ["https://t/a", "https://t/b"] and is_index is False
    index = "<sitemapindex><sitemap><loc>https://t/sm1.xml</loc></sitemap></sitemapindex>"
    locs, is_index = parse_sitemap(index)
    assert locs == ["https://t/sm1.xml"] and is_index is True


def test_decode_sitemap_handles_gzip():
    raw = b"<urlset><url><loc>https://t/z</loc></url></urlset>"
    assert "https://t/z" in _decode_sitemap("http://t/sitemap.xml.gz", gzip.compress(raw))
    assert "https://t/z" in _decode_sitemap("http://t/sitemap.xml", raw)  # plain too


def test_parse_openid_config_extracts_endpoints():
    cfg = {
        "issuer": "https://t",
        "authorization_endpoint": "https://t/oauth/authorize",
        "token_endpoint": "https://t/oauth/token",
        "jwks_uri": "https://t/jwks",
        "response_types_supported": ["code"],   # non-URL — ignored
        "grant_types": "not-a-url",              # non-URL — ignored
    }
    urls = parse_openid_config(cfg)
    assert set(urls) == {"https://t", "https://t/oauth/authorize", "https://t/oauth/token", "https://t/jwks"}
    assert parse_openid_config("not a dict") == []


def test_parse_security_txt_extracts_urls():
    txt = "Contact: mailto:sec@t\nContact: https://t/security\nPolicy: https://t/policy\n# x\n"
    assert parse_security_txt(txt) == ["https://t/security", "https://t/policy"]  # mailto skipped


# --- discover() flow (fake scope-enforced client) ------------------------

class _Resp:
    def __init__(self, status=200, text="", content=None, ctype="text/plain", json_data=None):
        self.status_code = status
        self.text = text
        self.content = content if content is not None else text.encode()
        self.headers = {"content-type": ctype}
        self._json = json_data

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


class _FakeHttp:
    def __init__(self, routes: dict):
        self.routes = routes

    async def get(self, url, follow_redirects=False):
        return self.routes.get(url, _Resp(404))


def _ctx(routes: dict):
    return types.SimpleNamespace(
        config=types.SimpleNamespace(target="http://t"),
        scope=ScopeValidator(ScopeConfig(domains=["t"], ports=[])),
        http=_FakeHttp(routes),
    )


def _collect(module, ctx):
    async def run():
        return [ep async for ep in module.discover(ctx)]
    return asyncio.run(run())


def test_robots_sitemap_discover_yields_endpoints():
    routes = {
        "http://t/robots.txt": _Resp(text="Disallow: /admin\nDisallow: /secret\nSitemap: http://t/sitemap.xml"),
        "http://t/sitemap.xml": _Resp(
            content=b"<urlset><url><loc>http://t/page1</loc></url><url><loc>http://t/page2</loc></url></urlset>",
            ctype="application/xml",
        ),
    }
    eps = _collect(RobotsSitemap(), _ctx(routes))
    urls = {e.url: e.source for e in eps}
    assert urls["http://t/admin"] == "robots"
    assert urls["http://t/secret"] == "robots"
    assert urls["http://t/page1"] == "sitemap" and urls["http://t/page2"] == "sitemap"


def test_robots_sitemap_follows_index_one_level():
    routes = {
        "http://t/robots.txt": _Resp(404),
        "http://t/sitemap.xml": _Resp(
            content=b"<sitemapindex><sitemap><loc>http://t/sm-a.xml</loc></sitemap></sitemapindex>",
            ctype="application/xml",
        ),
        "http://t/sm-a.xml": _Resp(
            content=b"<urlset><url><loc>http://t/deep</loc></url></urlset>", ctype="application/xml"),
    }
    urls = {e.url for e in _collect(RobotsSitemap(), _ctx(routes))}
    assert "http://t/deep" in urls  # discovered via the sitemap index


def test_well_known_discover_parses_oidc_and_security():
    routes = {
        "http://t/.well-known/openid-configuration": _Resp(
            json_data={
                "authorization_endpoint": "http://t/oauth/authorize",
                "token_endpoint": "http://t/oauth/token",
                "jwks_uri": "http://t/jwks",
            },
            ctype="application/json",
        ),
        "http://t/.well-known/security.txt": _Resp(text="Contact: https://t/report"),
    }
    eps = _collect(WellKnown(), _ctx(routes))
    urls = {e.url for e in eps}
    assert "http://t/.well-known/openid-configuration" in urls  # the doc itself
    assert {"http://t/oauth/authorize", "http://t/oauth/token", "http://t/jwks"} <= urls  # parsed
    assert "https://t/report" in urls  # from security.txt
    assert all(e.source == "well-known" for e in eps)
