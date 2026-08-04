"""Tests for the pure JS extractors."""

from __future__ import annotations

from orthrus.core.schemas import ParamLocation
from orthrus.recon.js_analyzer import (
    extract_endpoints,
    extract_secrets,
    extract_websockets,
    params_from_query,
)

BASE = "http://target.com/app/page"


def test_extract_endpoints_resolves_and_filters():
    js = """
        fetch('/api/users');
        axios.get('https://api.target.com/data');
        var x = "/api/v1/items";
        $.ajax({ url: '/submit' });
        var logo = '/assets/logo.png';
    """
    eps = extract_endpoints(js, BASE)
    assert "http://target.com/api/users" in eps
    assert "https://api.target.com/data" in eps
    assert "http://target.com/api/v1/items" in eps
    assert "http://target.com/submit" in eps
    assert not any(e.endswith("logo.png") for e in eps)


def test_extract_websockets():
    js = """
        var s = new WebSocket('wss://target.com/ws');
        var u = 'ws://target.com/live';
        var rel = new WebSocket('/socket');
    """
    ws = extract_websockets(js, "http://target.com/")
    assert "wss://target.com/ws" in ws
    assert "ws://target.com/live" in ws
    assert "ws://target.com/socket" in ws


def test_extract_secrets():
    aws = "AKIA" + "A" * 16            # AKIA + 16 chars
    google = "AIza" + "a" * 35         # AIza + 35 chars
    js = f"""
        const aws = "{aws}";
        const g = "{google}";
        const api_key = "supersecretvalue123";
    """
    labels = {label for label, _ in extract_secrets(js)}
    assert "AWS access key" in labels
    assert "Google API key" in labels
    assert "Generic secret assignment" in labels


def test_no_endpoints_or_secrets():
    assert extract_endpoints("var x = 1 + 2;", BASE) == set()
    assert extract_secrets("var x = 1;") == []


def test_extract_endpoints_preserves_query_string():
    # ginandjuice regression: a React filter map embeds the injectable link in an
    # inline script. The old path regex stopped at "?" and dropped the parameter,
    # so the SQLi scanner had no injection point to test.
    js = 'const categories = {"All":"/catalog","Gin":"/catalog?category=Gin"};'
    eps = extract_endpoints(js, "http://target.com/catalog")
    assert "http://target.com/catalog?category=Gin" in eps  # query survives
    assert "http://target.com/catalog" in eps               # bare route still found


def test_extract_endpoints_ignore_suffix_matches_path_only():
    # A "?query" must not defeat the static-asset filter, and a real endpoint
    # whose query merely ends in an asset-looking token must not be dropped.
    js = 'var a = "/assets/app.css?v=2"; var keep = "/search?q=1.css";'
    eps = extract_endpoints(js, "http://target.com/")
    assert not any("app.css" in e for e in eps)          # asset filtered despite ?v=2
    assert "http://target.com/search?q=1.css" in eps     # query ending in .css kept


def test_params_from_query_parses_query_params():
    params = params_from_query("http://t/catalog?category=Gin&sort=asc")
    got = {p.name: p.value for p in params}
    assert got == {"category": "Gin", "sort": "asc"}
    assert all(p.location is ParamLocation.QUERY for p in params)
    assert params_from_query("http://t/catalog") == []
