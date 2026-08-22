"""Known-pattern novelty gate - flag findings that are almost certainly already known.

A large share of scanner output is low-novelty: missing security headers,
directory listing, GraphQL introspection, weak SPF/DMARC - real, but so commonly
reported that they are near-always duplicates and low-bounty. This gate scores a
finding's novelty against a curated set of commonly-disclosed patterns so triage
can push scarce attention to the *novel* findings first.

It is deliberately a small, license-clean, authored seed (generic/OWASP common
knowledge - not a vendored third-party report corpus) - "the seed of a feed"
``orthrus update`` can grow. Pure and deterministic; complements the priority
engine (which scores exploitability) with a duplicate-likelihood signal.
"""

from __future__ import annotations

from dataclasses import dataclass

NOVEL, MEDIUM, LOW = "novel", "medium", "low"
_RANK = {LOW: 0, MEDIUM: 1, NOVEL: 2}


@dataclass(frozen=True)
class KnownPattern:
    vuln_class: str  # matches finding vuln_type, or "*" for any class
    keywords: tuple[str, ...]  # ALL must appear in title+description; () = class-only
    descriptor: str
    novelty: str  # LOW | MEDIUM


# Commonly-disclosed, low-novelty patterns (authored, generic).
KNOWN_PATTERNS: tuple[KnownPattern, ...] = (
    KnownPattern("clickjacking", (), "Missing frame protection (clickjacking)", LOW),
    KnownPattern("*", ("x-frame-options",), "Missing X-Frame-Options header", LOW),
    KnownPattern("*", ("content-security-policy",), "Missing/weak CSP", LOW),
    KnownPattern("*", ("strict-transport-security",), "Missing HSTS", LOW),
    KnownPattern("graphql", ("introspection",), "GraphQL introspection enabled", LOW),
    KnownPattern("directory-listing", (), "Directory listing enabled", LOW),
    KnownPattern("*", ("directory listing",), "Directory listing enabled", LOW),
    KnownPattern("cors", ("wildcard",), "CORS wildcard without credentials", LOW),
    KnownPattern("*", ("httponly",), "Cookie without HttpOnly", LOW),
    KnownPattern("*", ("secure flag",), "Cookie without Secure flag", LOW),
    KnownPattern("email-auth", (), "Weak SPF/DMARC email posture", LOW),
    KnownPattern("*", ("dmarc",), "Weak DMARC policy", LOW),
    KnownPattern("*", ("version disclosure",), "Server version/banner disclosure", LOW),
    KnownPattern("*", (".git",), "Exposed .git directory", MEDIUM),
    KnownPattern("*", (".env",), "Exposed .env file", MEDIUM),
    KnownPattern("framework-debug", ("actuator",), "Spring Actuator exposure", MEDIUM),
    KnownPattern("default-creds", (), "Default credentials", MEDIUM),
)


@dataclass(frozen=True)
class NoveltyVerdict:
    novelty: str  # LOW | MEDIUM | NOVEL
    matched: str | None  # descriptor of the matched pattern, if any
    note: str


def _get(finding: object, name: str) -> str:
    val = finding.get(name) if isinstance(finding, dict) else getattr(finding, name, None)
    val = getattr(val, "value", val)
    return str(val).lower() if val is not None else ""


def assess_novelty(
    finding: object, patterns: tuple[KnownPattern, ...] = KNOWN_PATTERNS
) -> NoveltyVerdict:
    """Score a finding's novelty; the lowest-novelty matching pattern wins."""
    vt = _get(finding, "vuln_type")
    text = f"{_get(finding, 'title')} {_get(finding, 'description')}"
    best: KnownPattern | None = None
    for p in patterns:
        if p.vuln_class not in ("*", vt):
            continue
        if p.keywords and not all(k in text for k in p.keywords):
            continue
        if best is None or _RANK[p.novelty] < _RANK[best.novelty]:
            best = p
    if best is None:
        return NoveltyVerdict(NOVEL, None, "no known-pattern match; treat as novel")
    return NoveltyVerdict(
        best.novelty,
        best.descriptor,
        f"matches a commonly-disclosed pattern ({best.novelty} novelty) - likely a known/duplicate issue",
    )


def partition_by_novelty(findings: list, patterns: tuple[KnownPattern, ...] = KNOWN_PATTERNS) -> dict:
    """Bucket findings into novel / medium / low for triage ordering."""
    buckets: dict[str, list] = {NOVEL: [], MEDIUM: [], LOW: []}
    for f in findings:
        buckets[assess_novelty(f, patterns).novelty].append(f)
    return buckets


__all__ = [
    "NOVEL",
    "MEDIUM",
    "LOW",
    "KnownPattern",
    "KNOWN_PATTERNS",
    "NoveltyVerdict",
    "assess_novelty",
    "partition_by_novelty",
]
