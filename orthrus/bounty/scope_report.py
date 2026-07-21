"""Personalised pre-engagement scope briefing from a program's scope export.

Parses a HackerOne scope CSV (identifier / asset_type / instruction / eligibility /
CIA requirements / max_severity) and renders an operator-facing Markdown briefing:
what is in and out of scope, the components/features to test, where the product is
available, the program's severity + CIA bar, and a suggested ORTHRUS testing focus
mapped from the scope's own language.

This reads the scope and nothing else - no requests are sent to any target.
"""

from __future__ import annotations

import csv
import io
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass
class ScopeAsset:
    """One row of a program's scope: an asset plus its testing instructions/policy."""

    identifier: str
    asset_type: str = ""
    instruction: str = ""
    eligible_for_bounty: bool = False
    eligible_for_submission: bool = False
    availability: str = ""
    confidentiality: str = ""
    integrity: str = ""
    max_severity: str = ""

    @property
    def host(self) -> str:
        """The hostname for URL/domain identifiers; '' for non-host rows (e.g. 'OTHER')."""
        s = (self.identifier or "").strip()
        if "://" in s:
            return (urlsplit(s).hostname or "").lower()
        head = s.split("/", 1)[0]
        return head.lower() if "." in head else ""


def _truthy(value) -> bool:
    return str(value or "").strip().lower() in ("true", "yes", "1")


def parse_h1_scope_csv(text: str) -> list[ScopeAsset]:
    """Parse a HackerOne scope CSV export into ScopeAssets (tolerant of missing columns)."""
    if not (text or "").strip():
        return []
    out: list[ScopeAsset] = []
    for row in csv.DictReader(io.StringIO(text)):
        ident = (row.get("identifier") or "").strip()
        if not ident:
            continue
        out.append(ScopeAsset(
            identifier=ident,
            asset_type=(row.get("asset_type") or "").strip(),
            instruction=row.get("instruction") or "",
            eligible_for_bounty=_truthy(row.get("eligible_for_bounty")),
            eligible_for_submission=_truthy(row.get("eligible_for_submission")),
            availability=(row.get("availability_requirement") or "").strip(),
            confidentiality=(row.get("confidentiality_requirement") or "").strip(),
            integrity=(row.get("integrity_requirement") or "").strip(),
            max_severity=(row.get("max_severity") or "").strip(),
        ))
    return out


_AVAIL_RE = re.compile(r"available[^:]*:\s*(.+)", re.IGNORECASE | re.DOTALL)


def _countries(instruction: str) -> list[str]:
    """Pull a comma-separated country-availability list out of an instruction blob."""
    m = _AVAIL_RE.search(instruction or "")
    if not m:
        return []
    raw = m.group(1).replace("**", "").strip().split("\n\n")[0]
    return [c.strip() for c in raw.split(",") if c.strip() and len(c.strip()) < 40]


def _bullets(instruction: str) -> list[str]:
    """Top-level '- item' bullets from an instruction (feature/component list)."""
    return [ln.strip()[2:].strip() for ln in (instruction or "").splitlines()
            if ln.strip().startswith("- ")]


def _in_out(instruction: str) -> tuple[list[str], list[str]]:
    """Split an instruction with 'In scope:' / 'Out of scope:' headers into (in, out)."""
    inn: list[str] = []
    out: list[str] = []
    bucket: list[str] | None = None
    for ln in (instruction or "").splitlines():
        s = ln.strip()
        low = s.lower()
        if low.startswith("in scope"):
            bucket = inn
        elif low.startswith(("out of scope", "out-of-scope")):
            bucket = out
        elif s.startswith("- ") and bucket is not None:
            bucket.append(s[2:].strip())
    return inn, out


def _mode(values) -> str:
    vals = [v for v in values if v]
    return Counter(vals).most_common(1)[0][0] if vals else ""


# scope-language keyword -> suggested ORTHRUS testing focus (most-specific first).
_FOCUS = [
    (("deposit", "withdraw", "payment", "voucher", "balance", "wallet", "transaction", "callback"),
     "**Payment / transaction flows** - open-redirect + CSRF on redirect/callback handling "
     "(automated); amount tampering, voucher reuse, and balance race conditions "
     "(**manual** - typically the highest-payout bugs)."),
    (("login", "registration", "register", "sign", "auth", "2fa", "otp", "session", "password"),
     "**Authentication & session** - `jwt`, `auth-session`, `oauth-flow`, `default-credentials`, "
     "`saml` (account-takeover class)."),
    (("personal", "settings", "profile", "details", "account", "voucher"),
     "**Access control / IDOR-BOLA** - `idor`, `authz-matrix` run with `--identities` "
     "(two accounts) for object- and function-level authorization."),
    (("betting", "casino", "game", "bet", "play", "search"),
     "**Injection & XSS** on game/bet inputs - `xss`, `sqli`, `nosql`, `ssti`, `graphql-injection`."),
    (("redirect", "url", "return", "next"),
     "**Open redirect / SSRF** - `open-redirect`, `ssrf` on redirect and return-URL parameters."),
]


def _testing_focus(assets: list[ScopeAsset]) -> list[str]:
    corpus = " ".join(f"{a.identifier} {a.instruction}" for a in assets).lower()
    return [tip for kws, tip in _FOCUS if any(k in corpus for k in kws)]


def render_scope_report(
    assets: list[ScopeAsset], *, program_name: str | None = None,
    source_name: str | None = None,
) -> str:
    """Render a personalised Markdown scope briefing for a program's scope."""
    if not assets:
        return "# Scope Report\n\n_No scope entries parsed._\n"

    in_scope = [a for a in assets if a.eligible_for_bounty] or assets
    hosts = [a.host for a in in_scope if a.host]
    primary = Counter(hosts).most_common(1)[0][0] if hosts else "the target"
    name = program_name or primary

    components: list[str] = []
    for a in in_scope:
        for b in _bullets(a.instruction):
            if b not in components and not b.lower().startswith(("infrastructure", "payment forms")):
                components.append(b)

    countries: list[str] = []
    for a in assets:
        for c in _countries(a.instruction):
            if c not in countries:
                countries.append(c)

    tech_in: list[str] = []
    tech_out: list[str] = []
    for a in assets:
        i, o = _in_out(a.instruction)
        tech_in += [x for x in i if x not in tech_in]
        tech_out += [x for x in o if x not in tech_out]

    sev = _mode(a.max_severity for a in in_scope)
    conf = _mode(a.confidentiality for a in in_scope)
    integ = _mode(a.integrity for a in in_scope)
    avail = _mode(a.availability for a in in_scope)
    types = sorted({a.asset_type for a in in_scope if a.asset_type})

    lines: list[str] = []
    lines.append(f"# {name} Bug Bounty Program Scope Report\n")
    if source_name:
        lines.append(f"> Generated by ORTHRUS from `{source_name}`. Reference only - "
                     "confirm against the live program policy before testing.\n")

    lines.append("## Overview\n")
    lines.append(f"We are participating in a Bug Bounty program for **{primary}**. The scope covers "
                 f"**{len(in_scope)} in-scope asset(s)**"
                 + (f" ({', '.join(types)})" if types else "") + ".\n")

    lines.append("## Scope Details\n")
    lines.append("### In-scope assets\n")
    lines.append("| Asset | Type | Bounty | Max severity |")
    lines.append("|---|---|---|---|")
    for a in in_scope:
        lines.append(f"| `{a.identifier}` | {a.asset_type or '-'} | "
                     f"{'yes' if a.eligible_for_bounty else 'no'} | {a.max_severity or '-'} |")
    lines.append("")

    if components:
        lines.append("### Main components\n")
        for c in components:
            lines.append(f"- **{c}**")
        lines.append("")

    if countries:
        lines.append("### Availability\n")
        lines.append(f"Available in {len(countries)} countries: "
                     + ", ".join(countries) + ".\n")

    if tech_in or tech_out:
        lines.append("### Technical scope\n")
        for x in tech_in:
            lines.append(f"- ✅ In scope: {x}")
        for x in tech_out:
            lines.append(f"- ⛔ Out of scope: {x}")
        lines.append("")

    lines.append("## Bug Bounty Program Details\n")
    lines.append("- **Eligibility:** in-scope assets flagged bounty-eligible above.")
    lines.append("- **Submission:** through the program's platform only.")
    if conf:
        lines.append(f"- **Confidentiality requirement:** {conf.title()}")
    if integ:
        lines.append(f"- **Integrity requirement:** {integ.title()}")
    if avail:
        lines.append(f"- **Availability requirement:** {avail.title()}")
    if sev:
        lines.append(f"- **Max severity:** {sev.title()}")
    lines.append("")

    focus = _testing_focus(assets)
    if focus:
        lines.append("## Suggested ORTHRUS testing focus\n")
        for tip in focus:
            lines.append(f"- {tip}")
        lines.append("")

    lines.append("## Next Steps\n")
    lines.append("- Conduct a thorough security audit of the identified components.")
    lines.append("- Identify potential vulnerabilities within each component.")
    lines.append("- Prepare detailed bug reports for submission to the Bug Bounty program.")
    lines.append("")
    lines.append("_Test only the in-scope assets, honour the program's rate limits and rules, "
                 "and never touch out-of-scope infrastructure._")
    return "\n".join(lines) + "\n"


__all__ = ["ScopeAsset", "parse_h1_scope_csv", "render_scope_report"]
