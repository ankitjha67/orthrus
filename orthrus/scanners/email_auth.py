"""Email-authentication posture scanner (SPF / DMARC / DKIM).

Passive DNS/OSINT: a domain with no (or monitor-only) DMARC can be spoofed in the
``From:`` header and delivered normally - the root enabler of phishing, spear
phishing and business email compromise. ``dns_enum`` already fetches the TXT
records but never interprets them; this scanner parses the sender-authentication
policy and reports where the domain is spoofable.

Only public DNS TXT/MX lookups are made (no packets to the target's web servers,
nothing intrusive), so this runs at PASSIVE aggressiveness. The verdict logic
(``classify_email_auth``) is pure and unit-tested; the dnspython layer is isolated
and degrades to no findings on error, mirroring ``tls_analyzer``.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger

logger = get_logger("scanner.email-auth")

SCANNER_NAME = "email-auth"

# Selectors probed when looking for a DKIM key. Selector names are arbitrary, so a
# negative result is only informational (a custom selector may still exist).
COMMON_DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "dkim", "mail", "smtp",
)


def _host_of(target: str) -> str:
    return (urlsplit(target if "://" in target else f"//{target}").hostname or target).lower()


def _spf_all_qualifier(spf: str) -> str | None:
    """Return the qualifier of the SPF ``all`` mechanism: '+', '-', '~', '?' or None.

    ``all`` with no explicit qualifier defaults to '+' (pass), per RFC 7208.
    """
    for token in spf.split():
        low = token.lower()
        if low == "all":
            return "+"
        if len(low) >= 4 and low[1:] == "all" and low[0] in "+-~?":
            return low[0]
    return None


def _dmarc_tag(record: str, tag: str) -> str | None:
    """Value of a DMARC ``tag=value`` pair (lower-cased), or None if absent."""
    for part in record.split(";"):
        k, sep, v = part.strip().partition("=")
        if sep and k.strip().lower() == tag.lower():
            return v.strip().lower()
    return None


def _dmarc_pct(record: str) -> int | None:
    raw = _dmarc_tag(record, "pct")
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def classify_email_auth(records: dict) -> list[tuple[Severity, str, str, str, str]]:
    """Map observed email-auth records to (severity, title, detail, cwe, remediation)."""
    issues: list[tuple[Severity, str, str, str, str]] = []
    has_mx = bool(records.get("mx"))
    ctx = " The domain publishes MX records and actively receives mail." if has_mx else ""

    # --- SPF ---
    spf = records.get("spf")
    spf_count = int(records.get("spf_count", 0) or 0)
    if not spf:
        issues.append((
            Severity.LOW, "No SPF record published",
            "The domain publishes no SPF (v=spf1) TXT record, so receivers have no policy to "
            "validate the envelope sender against." + ctx,
            "CWE-16",
            "Publish an SPF record listing only authorized senders and ending in -all (hardfail).",
        ))
    else:
        if spf_count > 1:
            issues.append((
                Severity.LOW, "Multiple SPF records (permerror)",
                f"{spf_count} v=spf1 TXT records are published; RFC 7208 permits exactly one, so "
                "SPF evaluation returns permerror and is effectively unenforced.",
                "CWE-16", "Merge the SPF records into a single TXT record.",
            ))
        qual = _spf_all_qualifier(spf)
        if qual in ("+", "?"):
            name = "+all (pass)" if qual == "+" else "?all (neutral)"
            issues.append((
                Severity.MEDIUM, f"SPF policy is permissive ({name})",
                f"The SPF record ends in '{qual}all', letting any host pass SPF for this domain "
                "and defeating the record's purpose.",
                "CWE-290", "End the SPF record in -all (hardfail); use ~all only during rollout.",
            ))

    # --- DMARC (walked up to the effective organizational policy) ---
    dmarc = records.get("dmarc")
    dmarc_source = records.get("dmarc_source")
    if not dmarc:
        issues.append((
            Severity.MEDIUM, "No DMARC record published",
            "No _dmarc TXT policy is published for the domain or its organizational parent, so a "
            "message spoofing this domain's From: address is delivered normally - the core enabler "
            "of phishing and business email compromise." + ctx,
            "CWE-290",
            "Publish a _dmarc record (start at p=none to observe, then move to p=reject).",
        ))
    else:
        policy = _dmarc_tag(dmarc, "p")
        src = f" (policy inherited from {dmarc_source})" if dmarc_source and dmarc_source != records.get("domain") else ""
        if policy in (None, "none"):
            issues.append((
                Severity.MEDIUM, "DMARC policy is monitor-only (p=none)",
                "The DMARC policy is p=none" + src + ", so receivers only send reports - they do "
                "not reject or quarantine spoofed mail, and the domain remains spoofable." + ctx,
                "CWE-290",
                "After confirming legitimate mail aligns, raise the policy to p=quarantine then p=reject.",
            ))
        else:
            # Enforcing (quarantine/reject): flag weakenings that reopen spoofing.
            if _dmarc_tag(dmarc, "sp") == "none":
                issues.append((
                    Severity.LOW, "DMARC subdomain policy is disabled (sp=none)",
                    "The organizational policy enforces, but sp=none leaves subdomains of this "
                    "domain spoofable.",
                    "CWE-290", "Set sp=reject/quarantine, or remove sp so subdomains inherit p.",
                ))
            pct = _dmarc_pct(dmarc)
            if pct is not None and pct < 100:
                issues.append((
                    Severity.LOW, f"DMARC is only partially enforced (pct={pct})",
                    f"Only {pct}% of mail is subject to the DMARC policy; the remainder is spoofable.",
                    "CWE-290", "Set pct=100 so the policy applies to all mail.",
                ))

    # --- DKIM (best-effort, informational) ---
    if records.get("dkim_checked") and not records.get("dkim_selectors_found"):
        issues.append((
            Severity.INFO, "No DKIM key found for common selectors",
            "No DKIM key resolved for the common selectors probed (a custom selector may still "
            "exist). Without DKIM, DMARC relies on SPF alone, which breaks when mail is forwarded.",
            "CWE-16", "Publish a DKIM key, sign outbound mail, and align the selector with DMARC.",
        ))

    return issues


def _txt(resolver, name: str) -> list[str]:  # type: ignore[no-untyped-def]
    try:
        answer = resolver.resolve(name, "TXT")
    except Exception:
        return []
    out: list[str] = []
    for rdata in answer:
        try:
            out.append(b"".join(rdata.strings).decode("utf-8", "replace"))
        except Exception:
            out.append(str(rdata).strip('"'))
    return out


def _base_domain(host: str) -> str:
    """Registrable domain via tldextract when available; else the exact host."""
    try:
        import tldextract

        reg = tldextract.extract(host).registered_domain
        if reg:
            return reg
    except Exception:
        pass
    return host


def _dmarc_candidates(domain: str) -> list[str]:
    """The domain and its parents (>= 2 labels) - a DMARC org-policy tree walk."""
    labels = domain.split(".")
    out: list[str] = []
    while len(labels) >= 2:
        out.append(".".join(labels))
        labels = labels[1:]
    return out[:4]


def _gather_email_records(host: str) -> dict | None:
    """Query SPF/DMARC/DKIM/MX for the target's organizational domain (blocking)."""
    try:
        import dns.resolver
    except Exception as exc:
        logger.debug("dnspython unavailable: %s", exc)
        return None

    domain = _base_domain(host)
    resolver = dns.resolver.Resolver()
    resolver.timeout = resolver.lifetime = 5.0

    out: dict = {
        "domain": domain, "spf": None, "spf_count": 0, "dmarc": None,
        "dmarc_source": None, "mx": [], "dkim_checked": True, "dkim_selectors_found": [],
    }

    spf_records = [t for t in _txt(resolver, domain) if t.lower().startswith("v=spf1")]
    out["spf_count"] = len(spf_records)
    out["spf"] = spf_records[0] if spf_records else None

    for candidate in _dmarc_candidates(domain):
        dmarc = [t for t in _txt(resolver, f"_dmarc.{candidate}") if t.lower().startswith("v=dmarc1")]
        if dmarc:
            out["dmarc"] = dmarc[0]
            out["dmarc_source"] = candidate
            break

    try:
        out["mx"] = sorted(str(r.exchange).rstrip(".") for r in resolver.resolve(domain, "MX"))
    except Exception:
        out["mx"] = []

    for selector in COMMON_DKIM_SELECTORS:
        recs = _txt(resolver, f"{selector}._domainkey.{domain}")
        if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in recs):
            out["dkim_selectors_found"].append(selector)

    return out


@register
class EmailAuthScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "email-auth"
    min_aggressiveness = Aggressiveness.PASSIVE

    def applicable(self, ctx: ScanContext) -> bool:
        host = _host_of(ctx.config.target)
        try:
            import ipaddress

            ipaddress.ip_address(host)
            return False  # email auth is a domain concept, not an IP one
        except ValueError:
            return host.count(".") >= 1

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        host = _host_of(ctx.config.target)
        if not ctx.scope.host_in_scope(host):
            logger.debug("email-auth: host %s not in scope; skipping", host)
            return

        records = await asyncio.to_thread(_gather_email_records, host)
        if not records:
            return

        domain = records.get("domain", host)
        url = f"https://{domain}/"
        for severity, title, detail, cwe, remediation in classify_email_auth(records):
            note = records.get("dmarc") if "DMARC" in title else records.get("spf")
            yield Finding(
                vuln_type="email-auth",
                title=title,
                severity=severity,
                confidence=Confidence.FIRM if severity is not Severity.INFO else Confidence.TENTATIVE,
                url=url,
                description=detail,
                remediation=remediation,
                cwe=cwe,
                scanner=SCANNER_NAME,
                evidence=Evidence(matched_at=domain, notes=str(note) if note else title),
            )


__all__ = [
    "EmailAuthScanner",
    "classify_email_auth",
    "_spf_all_qualifier",
    "_dmarc_tag",
    "_dmarc_pct",
    "_dmarc_candidates",
]
