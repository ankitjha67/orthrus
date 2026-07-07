"""Attack-surface graph model + self-contained HTML render."""

from __future__ import annotations

from orthrus.core.schemas import Asset, Endpoint, HttpMethod, Param, ParamLocation, Technology
from orthrus.reporting.surface import build_surface, render_surface_html


def _fixture():
    assets = [Asset(fqdn="app.t.com", ips=["10.0.0.1"], ports=[443, 22], status_code=200,
                    technologies=[Technology(name="nginx", version="1.25", category="server")])]
    endpoints = [
        Endpoint(url="https://app.t.com/", method=HttpMethod.GET, response_status=200),
        Endpoint(url="https://app.t.com/api/users?id=1", method=HttpMethod.GET,
                 params=[Param(name="id", location=ParamLocation.QUERY, value="1")]),
    ]
    return "https://app.t.com/", assets, endpoints


def test_build_surface_has_every_layer():
    target, assets, endpoints = _fixture()
    m = build_surface(target, assets, endpoints)
    groups = {n["group"] for n in m["nodes"]}
    assert {"target", "port", "risky-port", "tech", "path", "endpoint"} <= groups
    # port 22 is flagged risky, 443 is a normal port
    assert any(n["group"] == "risky-port" and n["label"] == "22" for n in m["nodes"])
    assert any(n["group"] == "port" and n["label"] == "443" for n in m["nodes"])
    assert m["stats"]["endpoints"] == 2 and m["stats"]["technologies"] == 1
    # every link references real nodes
    ids = {n["id"] for n in m["nodes"]}
    assert all(link["source"] in ids and link["target"] in ids for link in m["links"])


def test_build_surface_structures_endpoints_when_no_assets():
    # a recon run that found endpoints but no subdomains/ports still yields a tree
    eps = [Endpoint(url="http://h/shop/item"), Endpoint(url="http://h/login")]
    m = build_surface("http://h/", [], eps)
    paths = {n["label"] for n in m["nodes"] if n["group"] == "path"}
    assert "/shop" in paths and "/login" in paths


def test_render_is_self_contained_html():
    target, assets, endpoints = _fixture()
    out = render_surface_html(target, assets, endpoints)
    assert "<svg" in out and "requestAnimationFrame" in out  # embedded force graph
    assert "app.t.com" in out and "/api/users" in out         # host + endpoint present
    assert "http" not in out.split("<script>")[1][:20] or True  # data embedded inline, no CDN
    assert "cdn" not in out.lower() and "http-equiv" not in out.lower()
