"""Tests for the passive technology fingerprinter (pure, offline)."""

from __future__ import annotations

from hydra.recon.tech_fingerprint import extract_title, identify


def _names(techs) -> set[str]:
    return {t.name for t in techs}


def test_server_header_product_and_version():
    techs = identify({"Server": "nginx/1.25.3"}, "", [])
    nginx = next(t for t in techs if t.name == "nginx")
    assert nginx.version == "1.25.3"
    assert nginx.category == "server"


def test_powered_by_and_cookie_signatures():
    techs = identify(
        {"X-Powered-By": "PHP/8.2.1"},
        "",
        ["PHPSESSID=abc123; path=/"],
    )
    names = _names(techs)
    assert "PHP" in names


def test_generator_meta_detects_cms_with_version():
    body = '<meta name="generator" content="WordPress 6.4.2" />'
    techs = identify({}, body, [])
    wp = next(t for t in techs if t.name == "WordPress")
    assert wp.version == "6.4.2"
    assert wp.category == "cms"


def test_body_signature_js_library():
    body = '<script src="/static/jquery-3.6.0.min.js"></script>'
    techs = identify({}, body, [])
    assert "jQuery" in _names(techs)


def test_extract_title():
    assert extract_title("<html><head><title>  Hello   World </title></head>") == "Hello World"
    assert extract_title("<html><head></head>") is None


def test_no_signals_yields_nothing():
    assert identify({}, "<html></html>", []) == []
