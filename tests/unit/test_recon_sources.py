"""Pure-Python recon sources: parsing/filtering with injected fetch + resolve."""

from __future__ import annotations

import asyncio

from orthrus.recon.subdomain_enum import SUB_WORDLIST
from orthrus.recon_engine import RECON_REGISTRY, ReconScope
from orthrus.recon_engine.sources import (
    CertspotterAdapter,
    CrtShAdapter,
    DnsBruteAdapter,
    WaybackAdapter,
)

_SCOPE = ReconScope(domains=["acme.com"])


def test_sources_registered():
    for name in ("crtsh", "certspotter", "dns-brute", "wayback"):
        assert name in RECON_REGISTRY


def test_crtsh_extracts_in_domain_subdomains(monkeypatch):
    entries = [{"name_value": "api.acme.com\n*.acme.com"}, {"name_value": "evil.com"}]

    async def fake_json(url):
        return entries

    monkeypatch.setattr("orthrus.recon_engine.sources._get_json", fake_json)
    res = asyncio.run(CrtShAdapter().discover(_SCOPE))
    assert {a.value for a in res} == {"api.acme.com", "acme.com"}   # evil.com filtered
    assert all(a.kind == "subdomain" and a.source == "crtsh" for a in res)


def test_certspotter_filters_and_strips_wildcards(monkeypatch):
    issuances = [
        {"dns_names": ["api.acme.com", "*.acme.com", "acme.com", "other.org"]},
        {"dns_names": ["www.acme.com"]},
    ]

    async def fake_json(url):
        return issuances

    monkeypatch.setattr("orthrus.recon_engine.sources._get_json", fake_json)
    res = asyncio.run(CertspotterAdapter().discover(_SCOPE))
    assert {a.value for a in res} == {"api.acme.com", "acme.com", "www.acme.com"}


def test_dns_brute_keeps_only_resolving_hosts(monkeypatch):
    target = f"{SUB_WORDLIST[0]}.acme.com"

    async def fake_resolve(name):
        return ["1.2.3.4"] if name == target else []

    monkeypatch.setattr("orthrus.recon_engine.sources._resolve", fake_resolve)
    res = asyncio.run(DnsBruteAdapter().discover(_SCOPE))
    assert [a.value for a in res] == [target]
    assert res[0].metadata["ips"] == ["1.2.3.4"]


def test_wayback_yields_url_assets(monkeypatch):
    async def fake_text(url):
        return "https://acme.com/a\nhttps://api.acme.com/b?x=1\n\n"

    monkeypatch.setattr("orthrus.recon_engine.sources._get_text", fake_text)
    res = asyncio.run(WaybackAdapter().discover(_SCOPE))
    assert [a.value for a in res] == ["https://acme.com/a", "https://api.acme.com/b?x=1"]
    assert all(a.kind == "url" and a.metadata.get("historical") for a in res)
