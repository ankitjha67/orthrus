"""Tests for the pure JS extractors."""

from __future__ import annotations

from hydra.recon.js_analyzer import extract_endpoints, extract_secrets, extract_websockets

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
