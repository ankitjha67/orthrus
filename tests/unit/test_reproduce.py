"""Per-finding reproduction snippets (curl / Python / raw HTTP)."""

from __future__ import annotations

from orthrus.reporting.reproduce import build_snippets

_RAW_POST = (
    "POST /search?q=hi HTTP/1.1\r\n"
    "Host: shop.example\r\n"
    "Cookie: session=abc123\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 7\r\n"
    "\r\n"
    "name=x'y"
)


def test_post_snippets_from_raw():
    s = build_snippets(url="https://shop.example/search?q=hi", request_raw=_RAW_POST)
    assert set(s) == {"curl", "python", "raw"}
    # curl: method, url, kept + dropped headers, body
    assert "curl -sk -X POST 'https://shop.example/search?q=hi'" in s["curl"]
    assert "-H 'Cookie: session=abc123'" in s["curl"]
    assert "Host:" not in s["curl"] and "Content-Length:" not in s["curl"]  # client-managed
    assert "--data 'name=x'\\''y'" in s["curl"]  # single-quote is shell-escaped
    # python: method + url + body present
    assert "'POST'" in s["python"] and "shop.example/search" in s["python"]
    assert "verify=False" in s["python"]
    # raw: valid request line for Burp Repeater
    assert s["raw"].startswith("POST /search?q=hi HTTP/1.1")
    assert "Cookie: session=abc123" in s["raw"]


def test_get_snippet_from_url_only():
    s = build_snippets(url="https://api.example/v1/users/7", request_raw=None)
    assert s["curl"] == "curl -sk 'https://api.example/v1/users/7'"  # no -X for GET
    assert "'GET'" in s["python"]


def test_origin_form_request_without_host_borrows_from_url():
    # path-only request line, no Host header -> must not raise; Host comes from the URL
    raw = "GET /a?x=1 HTTP/1.1\r\nAccept: */*\r\n\r\n"
    s = build_snippets(url="http://target.local:8791/a?x=1", request_raw=raw)
    assert "curl -sk 'http://target.local:8791/a?x=1'" in s["curl"]
    assert s["raw"].startswith("GET /a?x=1 HTTP/1.1")


def test_non_http_request_raw_falls_back_to_url_get():
    # some scanners stash a payload description / GraphQL dict in request_raw;
    # it must NOT become a garbage `curl -X {'QUERY':...` - fall back to a clean GET
    for junk in ("{'query': 'mutation{...}'}", "HOST=127.0.0.1; id", "MULTIPART upload: x"):
        s = build_snippets(url="http://127.0.0.1:8791/graphql", request_raw=junk)
        assert s["curl"] == "curl -sk 'http://127.0.0.1:8791/graphql'"
        assert "-X" not in s["curl"]  # GET, no bogus method


def test_empty_when_nothing_to_reproduce():
    assert build_snippets(url=None, request_raw=None) == {}
    assert build_snippets(url="", request_raw="   ") == {}
