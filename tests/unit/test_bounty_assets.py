"""Bug-bounty wildcard expansion: subdomain discovery + in-scope filtering."""

from __future__ import annotations

from orthrus.bounty.assets import discover_subdomains, expand_program, in_scope_seeds
from orthrus.bounty.scope_intake import parse_program_scope


def test_in_scope_seeds_filters_and_dedupes():
    ps = parse_program_scope("*.example.com\n!admin.example.com\n")
    hosts = [
        "www.example.com", "api.example.com", "admin.example.com",  # excluded
        "evil.com",                                                  # off-scope
        "portal.example.gov",                                        # kill-listed
        "www.example.com",                                          # duplicate
    ]
    assert in_scope_seeds(hosts, ps) == ["https://www.example.com", "https://api.example.com"]


async def test_discover_suppresses_wildcard_and_dead():
    resolved = {
        "a.example.com": ["1.1.1.1"],          # real host
        "b.example.com": ["9.9.9.9"],          # resolves to the catch-all IP -> suppressed
        "dead.example.com": [],                # no A record -> skipped
    }

    async def fake_resolve(name: str) -> list[str]:
        if name.startswith("orthrus-"):        # the random wildcard probe
            return ["9.9.9.9"]
        return resolved.get(name, [])

    async def fake_crtsh(domain: str) -> list[str]:
        return ["a.example.com", "b.example.com", "dead.example.com"]

    live = await discover_subdomains("example.com", resolve=fake_resolve, crtsh=fake_crtsh, brute=False)
    assert live == ["a.example.com"]


async def test_expand_program_keeps_only_authorized_hosts():
    ps = parse_program_scope("*.example.com\n!admin.example.com\n")

    async def fake_discover(domain: str) -> list[str]:
        return ["www.example.com", "admin.example.com", "portal.example.gov", "other.com"]

    seeds = await expand_program(ps, discover=fake_discover)
    assert seeds == ["https://www.example.com"]  # excluded / kill-listed / off-scope all dropped


async def test_expand_program_survives_discovery_error():
    ps = parse_program_scope("*.example.com\n")

    async def boom(domain: str) -> list[str]:
        raise RuntimeError("crt.sh down")

    assert await expand_program(ps, discover=boom) == []  # error swallowed, campaign continues
