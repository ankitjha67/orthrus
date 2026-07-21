"""Reject-list for high-sensitivity targets (PRD §2.3 / §8.5 / §11).

Some hosts must not be scanned casually even inside an otherwise-authorized
program: government and military systems, and - with a softer warning -
education and healthcare. Testing these without specific, documented
authorization is a fast route to criminal exposure, so ORTHRUS refuses them by
default and only proceeds on an explicit, per-host typed acknowledgment that the
operator holds written authorization.

This is deliberately conservative and TLD/keyword-based (not a live registry
lookup): it is a *safety brake*, not a legal determination. It errs toward
refusing; a false positive costs one `--i-am-authorized` flag, a false negative
could be a crime.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Government / military: refuse by default (bypass = explicit per-host ack).
# Covers the US-style bare TLDs and common national government second-level TLDs.
_GOV_MIL_SUFFIXES = (
    ".gov", ".mil", ".fed.us",
    ".gov.uk", ".mod.uk", ".nhs.uk",
    ".gc.ca", ".gouv.fr", ".gov.au", ".govt.nz", ".gov.in", ".nic.in",
    ".gov.sg", ".gov.za", ".gov.br", ".gob.mx", ".gob.es", ".admin.ch",
    ".bund.de", ".gov.it", ".go.jp", ".gov.cn",
    ".mil.uk", ".mil.in", ".mil.au", ".mil.za", ".mil.br",
)
# Softer tier: warn + require acknowledgment, but the class is often legitimately
# in bug-bounty scope (many universities/health systems run programs).
_SENSITIVE_SUFFIXES = (".edu", ".ac.uk", ".edu.au", ".edu.cn", ".ac.jp", ".edu.in")
_SENSITIVE_KEYWORDS = ("hospital", "healthcare", "election", "ballot", "911", "emergency")

# Sanctioned ccTLDs ORTHRUS declines by default (self-hosted operators are still
# legally responsible; this is a guardrail, not a control).
_SANCTIONED_SUFFIXES = (".ru", ".by", ".kp", ".ir", ".sy")


@dataclass(frozen=True)
class KillListDecision:
    host: str
    category: str            # 'government-military' | 'education-health' | 'sanctioned'
    reason: str
    hard: bool               # True = refuse unless per-host acknowledgment


def _host_suffix_match(host: str, suffixes) -> str | None:
    host = (host or "").lower().rstrip(".")
    for suf in suffixes:
        s = suf.lstrip(".")
        if host == s or host.endswith("." + s):
            return suf
    return None


def classify(host: str) -> KillListDecision | None:
    """Return a decision if ``host`` is high-sensitivity, else ``None``."""
    host = (host or "").lower().strip().rstrip(".")
    if not host:
        return None
    gm = _host_suffix_match(host, _GOV_MIL_SUFFIXES)
    if gm:
        return KillListDecision(host, "government-military",
                                f"'{host}' looks like government/military infrastructure ({gm})", True)
    sanc = _host_suffix_match(host, _SANCTIONED_SUFFIXES)
    if sanc:
        return KillListDecision(host, "sanctioned",
                                f"'{host}' is in a sanctioned-jurisdiction TLD ({sanc})", True)
    edu = _host_suffix_match(host, _SENSITIVE_SUFFIXES)
    if edu:
        return KillListDecision(host, "education-health",
                                f"'{host}' looks like an education domain ({edu})", True)
    if any(re.search(rf"(^|[.\-]){re.escape(k)}([.\-]|$)", host) for k in _SENSITIVE_KEYWORDS):
        return KillListDecision(host, "education-health",
                                f"'{host}' matches a healthcare/emergency/election keyword", True)
    return None


def screen(hosts: list[str], *, acknowledged: set[str] | None = None) -> list[KillListDecision]:
    """Return the blocking decisions for ``hosts`` not covered by an acknowledgment.

    ``acknowledged`` is the set of hosts (lowercased) the operator has explicitly
    attested written authorization for (``--i-am-authorized``).
    """
    ack = {h.lower().rstrip(".") for h in (acknowledged or set())}
    seen: set[str] = set()
    out: list[KillListDecision] = []
    for host in hosts:
        h = (host or "").lower().rstrip(".")
        if not h or h in seen:
            continue
        seen.add(h)
        decision = classify(h)
        if decision and h not in ack:
            out.append(decision)
    return out


__all__ = ["KillListDecision", "classify", "screen"]
