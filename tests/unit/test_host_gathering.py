"""Host gathering: source parsing, consolidation, scope flagging, asset emit."""

from __future__ import annotations

from types import SimpleNamespace

import orthrus.recon.host_gathering as hg
from orthrus.core.config import ScopeConfig
from orthrus.recon.host_gathering import (
    HostGathering,
    gather_hosts,
    hosts_from_urls,
    net24_addresses,
    parse_reverse_ip,
    valid_hostname,
)
from orthrus.utils.scope import ScopeValidator


# ----------------------------------------------------------- pure helpers
def test_valid_hostname_accepts_domains_rejects_ips_and_junk():
    assert valid_hostname("example.com")
    assert valid_hostname("a.b.example.co.uk")
    assert not valid_hostname("1.2.3.4")  # IP literal
    assert not valid_hostname("nodot")
    assert not valid_hostname("")
    assert not valid_hostname("bad host.com")


def test_parse_reverse_ip_filters_noise_and_ips():
    text = "a.com\nB.Example.ORG\nerror: nothing\napi count exceeded\n1.2.3.4\na.com\n"
    assert parse_reverse_ip(text) == ["a.com", "b.example.org"]


def test_hosts_from_urls():
    urls = ["https://a.example.com/x", "http://b.example.com/", "a.example.com/y"]
    assert hosts_from_urls(urls) == ["a.example.com", "b.example.com"]


def test_net24_addresses():
    addrs = net24_addresses("178.79.134.182")
    assert len(addrs) == 256
    assert addrs[0] == "178.79.134.0" and addrs[-1] == "178.79.134.255"
    assert net24_addresses("2001:db8::1") == []  # IPv6 not swept
    assert net24_addresses("not-an-ip") == []


def test_net24_addresses_cap():
    assert len(net24_addresses("10.0.0.5", cap=10)) == 10


# --------------------------------------------------------- gather_hosts()
def _patch_sources(monkeypatch, *, crtsh=None, wayback=None, revip=None, ptr=None, resolve=None):
    async def _crtsh(domain):
        return list(crtsh or [])

    async def _way(domain):
        return list(wayback or [])

    async def _rev(ip):
        return list(revip or [])

    async def _ptr(ip, cap=256):
        return list(ptr or [])

    async def _res(host):
        return list((resolve or {}).get(host, []))

    monkeypatch.setattr(hg, "_crtsh_hosts", _crtsh)
    monkeypatch.setattr(hg, "_wayback_hosts", _way)
    monkeypatch.setattr(hg, "_reverse_ip_hosts", _rev)
    monkeypatch.setattr(hg, "_netblock_ptr_sweep", _ptr)
    monkeypatch.setattr(hg, "_resolve_ips", _res)


async def test_gather_consolidates_dedupes_and_flags_scope(monkeypatch):
    _patch_sources(
        monkeypatch,
        crtsh=["api.example.com", "www.example.com"],
        wayback=["www.example.com", "old.example.com"],
        revip=["shared-tenant.net", "api.example.com"],  # api also via reverse-ip
        ptr=["mail.example.com", "neighbor.other.org"],
        resolve={"example.com": ["93.184.216.34"]},
    )
    scope = ScopeValidator(ScopeConfig(domains=["example.com", "*.example.com"]))
    rows = await gather_hosts("example.com", scope)

    by_fqdn = {g.fqdn: g for g in rows}
    # in-scope example.com hosts gathered, deduped
    assert {"example.com", "api.example.com", "www.example.com",
            "old.example.com", "mail.example.com"} <= set(by_fqdn)
    # multi-source host carries both sources
    assert set(by_fqdn["api.example.com"].sources) == {"crt.sh", "reverse-ip"}
    # out-of-scope co-hosted hosts are gathered but flagged
    assert by_fqdn["shared-tenant.net"].in_scope is False
    assert by_fqdn["neighbor.other.org"].in_scope is False
    assert by_fqdn["api.example.com"].in_scope is True
    # in-scope hosts sort before out-of-scope
    assert rows[0].in_scope is True and rows[-1].in_scope is False


async def test_gather_respects_disabled_sources(monkeypatch):
    called = {"revip": False, "ptr": False}

    async def _rev(ip):
        called["revip"] = True
        return []

    async def _ptr(ip, cap=256):
        called["ptr"] = True
        return []

    _patch_sources(monkeypatch, crtsh=["a.example.com"], resolve={"example.com": ["1.1.1.1"]})
    monkeypatch.setattr(hg, "_reverse_ip_hosts", _rev)
    monkeypatch.setattr(hg, "_netblock_ptr_sweep", _ptr)

    scope = ScopeValidator(ScopeConfig(domains=["example.com", "*.example.com"]))
    await gather_hosts("example.com", scope, reverse_ip=False, netblock=False)
    assert called == {"revip": False, "ptr": False}


# --------------------------------------------------- HostGathering.discover
async def test_discover_emits_only_in_scope_assets(monkeypatch):
    _patch_sources(
        monkeypatch,
        crtsh=["api.example.com"],
        revip=["shared-tenant.net"],  # out of scope - must NOT become an Asset
        resolve={"example.com": ["93.184.216.34"]},
    )
    scope = ScopeValidator(ScopeConfig(domains=["example.com", "*.example.com"]))
    ctx = SimpleNamespace(config=SimpleNamespace(target="https://example.com/"), scope=scope)
    assets = [a async for a in HostGathering().discover(ctx)]
    fqdns = {a.fqdn for a in assets}
    assert "api.example.com" in fqdns
    assert "shared-tenant.net" not in fqdns  # co-hosted, out of scope
    assert all(a.discovery_method.startswith("host-gather") for a in assets)


async def test_discover_skips_out_of_scope_target(monkeypatch):
    def _boom(_h):  # pragma: no cover
        raise AssertionError("gathered an out-of-scope target")

    monkeypatch.setattr(hg, "gather_hosts", _boom)
    scope = ScopeValidator(ScopeConfig(domains=["example.com"]))
    ctx = SimpleNamespace(config=SimpleNamespace(target="https://evil.test/"), scope=scope)
    assert [a async for a in HostGathering().discover(ctx)] == []
