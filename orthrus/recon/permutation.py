"""Subdomain permutation / mutation generation (altdns / dnsgen style).

Certificate Transparency and a static brute-force wordlist both miss subdomains
that are *variations* of ones you already found - ``api`` implies ``api-dev``,
``dev-api``, ``api2``, ``staging-api``. m0chan's ``InitialBountyEnum.sh`` runs
``altdns`` for exactly this reason. Given the labels discovered from CT, this
generates bounded permutations for the resolver to try, widening the attack
surface without an external tool.

Pure and dependency-free: it only builds candidate names; ``SubdomainEnum``
resolves them through the scoped resolver and keeps the ones that answer.
"""

from __future__ import annotations

# Environment / role words that commonly prefix or suffix a real subdomain.
PERMUTE_WORDS = (
    "dev", "development", "staging", "stage", "prod", "production", "test", "testing",
    "uat", "qa", "sandbox", "demo", "beta", "alpha", "internal", "int", "admin", "api",
    "app", "portal", "dashboard", "old", "new", "v1", "v2", "v3", "backup", "bak",
    "corp", "git", "gw", "gateway", "vpn", "cdn", "edge", "preprod", "mgmt",
)

MAX_LABEL = 63  # DNS label length limit
MAX_FQDN = 253


def sub_labels(subs: list[str], domain: str) -> list[str]:
    """Distinct DNS labels appearing to the left of ``domain`` in discovered subs.

    ``api.staging.example.com`` under ``example.com`` contributes ``api`` and
    ``staging``. Non-label junk (wildcards, empty parts) is dropped.
    """
    domain = domain.lower().strip(".")
    labels: set[str] = set()
    for raw in subs:
        host = (raw or "").lower().strip().rstrip(".")
        if not host.endswith("." + domain) or host == domain:
            continue
        prefix = host[: -(len(domain) + 1)]
        for part in prefix.split("."):
            if part and part != "*" and all(c.isalnum() or c == "-" for c in part):
                labels.add(part.strip("-"))
    labels.discard("")
    return sorted(labels)


def permutations(
    labels: list[str], domain: str, words: tuple[str, ...] = PERMUTE_WORDS, *, cap: int = 150
) -> list[str]:
    """Bounded permutation FQDNs derived from ``labels`` under ``domain``.

    For each label: numeric bumps and old/new variants, plus dash-joined and
    concatenated combinations with each role word (both orders). Deduplicated,
    length-checked, and capped so the resolver load stays predictable.
    """
    domain = domain.lower().strip(".")
    out: list[str] = []
    seen: set[str] = set()

    def add(mut: str) -> bool:
        mut = mut.strip("-.")
        if not mut or len(mut) > MAX_LABEL:
            return len(out) < cap
        fqdn = f"{mut}.{domain}"
        if fqdn not in seen and len(fqdn) <= MAX_FQDN:
            seen.add(fqdn)
            out.append(fqdn)
        return len(out) < cap

    for label in labels:
        if not add(f"{label}1") or not add(f"{label}2"):
            break
        if not add(f"{label}-old") or not add(f"{label}-new"):
            break
        exhausted = False
        for word in words:
            for mut in (f"{word}-{label}", f"{label}-{word}", f"{word}{label}", f"{label}{word}"):
                if not add(mut):
                    exhausted = True
                    break
            if exhausted:
                break
        if exhausted:
            break
    return out


__all__ = ["PERMUTE_WORDS", "sub_labels", "permutations"]
