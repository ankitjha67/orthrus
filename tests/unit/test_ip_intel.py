"""IP-address intelligence recon: Cymru parsing, cloud attribution, scope gates."""

from __future__ import annotations

from types import SimpleNamespace

import orthrus.recon.ip_intel as ip_intel
from orthrus.core.config import ScopeConfig
from orthrus.core.schemas import Asset, IpIntel
from orthrus.recon.ip_intel import (
    IpIntelRecon,
    _origin_query,
    attribute_cloud,
    parse_cymru_asname,
    parse_cymru_origin,
)
from orthrus.utils.scope import ScopeValidator


def _ctx(target: str, scope: ScopeValidator):
    return SimpleNamespace(config=SimpleNamespace(target=target), scope=scope)


# ----------------------------------------------------------- Cymru parsing
def test_parse_cymru_origin_happy():
    out = parse_cymru_origin('"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"')
    assert out == {
        "asn": "15169",
        "network": "8.8.8.0/24",
        "country": "US",
        "registry": "arin",
        "allocated": "2023-12-28",
    }


def test_parse_cymru_origin_multi_origin_takes_first_asn():
    out = parse_cymru_origin("15169 36040 | 8.8.8.0/24 | US | arin | 2023-12-28")
    assert out["asn"] == "15169"


def test_parse_cymru_origin_malformed_returns_empty():
    assert parse_cymru_origin("garbage") == {}
    assert parse_cymru_origin("a | b") == {}


def test_parse_cymru_asname():
    assert parse_cymru_asname("15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US") == (
        "GOOGLE - Google LLC, US"
    )
    assert parse_cymru_asname("15169 | US | arin") is None


# ------------------------------------------------------- cloud attribution
def test_attribute_cloud_known_providers():
    assert attribute_cloud("GOOGLE - Google LLC, US") == "Google Cloud"
    assert attribute_cloud("AMAZON-02, US") == "AWS"
    assert attribute_cloud("MICROSOFT-CORP-MSN-AS-BLOCK, US") == "Azure"
    assert attribute_cloud("CLOUDFLARENET, US") == "Cloudflare"


def test_attribute_cloud_unknown_is_none():
    assert attribute_cloud("SOME-LOCAL-ISP, IN") is None
    assert attribute_cloud(None) is None


# ------------------------------------------------------------ query naming
def test_origin_query_ipv4_reverses_octets():
    assert _origin_query("1.2.3.4") == "4.3.2.1.origin.asn.cymru.com"


def test_origin_query_ipv6_uses_origin6():
    q = _origin_query("2001:4860:4860::8888")
    assert q.endswith(".origin6.asn.cymru.com")
    assert "ip6.arpa" not in q


# --------------------------------------------------------- schema round-trip
def test_ip_intel_survives_asset_roundtrip():
    intel = IpIntel(
        ip="8.8.8.8", asn="AS15169", cloud_provider="Google Cloud", ptr=["dns.google"]
    )
    asset = Asset(fqdn="example.com", ips=["8.8.8.8"], ip_intel=intel, discovery_method="ip-intel")
    restored = Asset.model_validate(asset.model_dump(mode="json"))
    assert restored.ip_intel.asn == "AS15169"
    assert restored.ip_intel.cloud_provider == "Google Cloud"
    assert restored.ip_intel.ptr == ["dns.google"]


# --------------------------------------------------------------- discover()
def _patch_dns(monkeypatch, ips, ptr, cymru):
    async def fake_resolve(host):
        return list(ips)

    async def fake_ptr(resolver, ip):
        return list(ptr)

    async def fake_cymru(resolver, ip):
        return dict(cymru)

    monkeypatch.setattr(ip_intel, "_resolve_ips", fake_resolve)
    monkeypatch.setattr(ip_intel, "_reverse_ptr", fake_ptr)
    monkeypatch.setattr(ip_intel, "_cymru_lookup", fake_cymru)


async def test_discover_enriches_in_scope_target(monkeypatch):
    _patch_dns(
        monkeypatch,
        ips=["8.8.8.8"],
        ptr=["dns.google"],
        cymru={
            "asn": "AS15169",
            "network": "8.8.8.0/24",
            "country": "US",
            "registry": "arin",
            "allocated": "2023-12-28",
            "as_org": "GOOGLE - Google LLC, US",
        },
    )
    scope = ScopeValidator(ScopeConfig(domains=["example.com"]))
    assets = [a async for a in IpIntelRecon().discover(_ctx("https://example.com/", scope))]
    assert len(assets) == 1
    a = assets[0]
    assert a.discovery_method == "ip-intel"
    assert a.ips == ["8.8.8.8"]
    assert a.ip_intel.asn == "AS15169"
    assert a.ip_intel.as_org == "GOOGLE - Google LLC, US"
    assert a.ip_intel.cloud_provider == "Google Cloud"
    assert a.ip_intel.ptr == ["dns.google"]
    assert a.ip_intel.country == "US"


async def test_discover_skips_out_of_scope_target(monkeypatch):
    # An out-of-scope target must yield nothing - and never even resolve.
    def _boom(_host):  # pragma: no cover - must not be called
        raise AssertionError("resolution attempted on an out-of-scope target")

    monkeypatch.setattr(ip_intel, "_resolve_ips", _boom)
    scope = ScopeValidator(ScopeConfig(domains=["example.com"]))
    assets = [a async for a in IpIntelRecon().discover(_ctx("https://evil.test/", scope))]
    assert assets == []


async def test_discover_honors_declared_ip_ranges(monkeypatch):
    # Domain is in scope, but the resolved IP falls outside a declared range.
    _patch_dns(monkeypatch, ips=["8.8.8.8"], ptr=[], cymru={})
    scope = ScopeValidator(ScopeConfig(domains=["example.com"], ip_ranges=["10.0.0.0/8"]))
    assets = [a async for a in IpIntelRecon().discover(_ctx("https://example.com/", scope))]
    assert assets == []  # per-IP range gate suppressed it
