"""Authentication & session security scanner (PRD §6.6).

Passive: Set-Cookie security attributes (Secure / HttpOnly / SameSite) and
session-token entropy (predictable/low-entropy tokens). Default-credential
testing lives in the separate ``default-credentials`` scanner.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from hydra.core.context import ScanContext
from hydra.core.schemas import Confidence, Evidence, Finding, Severity
from hydra.scanners.base_scanner import BaseScanner
from hydra.scanners.registry import register

SCANNER_NAME = "auth-session"
_SESSION_HINTS = ("sess", "sid", "token", "auth", "jwt", "csrf")
MIN_TOKEN_BITS = 64


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def token_strength_bits(value: str) -> float:
    return shannon_entropy(value) * len(value)


def is_session_cookie(name: str) -> bool:
    lower = name.lower()
    return any(h in lower for h in _SESSION_HINTS)


def cookie_issues(set_cookie: str, is_https: bool) -> list[tuple[str, Severity, str, str]]:
    """Return (cookie_name, severity, title, cwe) for each missing protection."""
    parts = [p.strip() for p in set_cookie.split(";")]
    if not parts or "=" not in parts[0]:
        return []
    name = parts[0].split("=", 1)[0].strip()
    attrs = {p.split("=", 1)[0].strip().lower() for p in parts[1:]}
    issues: list[tuple[str, Severity, str, str]] = []
    if is_https and "secure" not in attrs:
        issues.append((name, Severity.MEDIUM, "Cookie set without Secure flag", "CWE-614"))
    if "httponly" not in attrs:
        issues.append((name, Severity.LOW, "Cookie set without HttpOnly flag", "CWE-1004"))
    if "samesite" not in attrs:
        issues.append((name, Severity.LOW, "Cookie set without SameSite attribute", "CWE-1275"))
    return issues


_REMEDIATION = {
    "CWE-614": "Set the Secure flag so cookies are only sent over HTTPS.",
    "CWE-1004": "Set HttpOnly so cookies are inaccessible to JavaScript (mitigates XSS theft).",
    "CWE-1275": "Set SameSite=Lax or Strict to mitigate cross-site request forgery.",
}


@register
class AuthSessionScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "auth-session"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen: set[tuple[str, str, str]] = set()
        for endpoint in ctx.endpoints:
            if not endpoint.set_cookies:
                continue
            split = urlsplit(endpoint.url)
            is_https = split.scheme == "https"
            host = split.netloc
            for line in endpoint.set_cookies:
                for name, severity, title, cwe in cookie_issues(line, is_https):
                    key = (host, name, title)
                    if key in seen:
                        continue
                    seen.add(key)
                    yield Finding(
                        vuln_type="auth-session",
                        title=f"{title} ('{name}')",
                        severity=severity,
                        confidence=Confidence.FIRM,
                        url=endpoint.url,
                        description=(
                            f"The cookie '{name}' is missing a security attribute ({title}), "
                            "weakening session protection."
                        ),
                        remediation=_REMEDIATION.get(cwe, ""),
                        cwe=cwe,
                        scanner=SCANNER_NAME,
                        evidence=Evidence(matched_at=name, notes=line),
                    )

                # Session-token entropy.
                first = line.split(";", 1)[0]
                if "=" not in first:
                    continue
                cname, _, cvalue = first.partition("=")
                cname = cname.strip()
                if not is_session_cookie(cname) or len(cvalue) < 4:
                    continue
                bits = token_strength_bits(cvalue)
                key = (host, cname, "entropy")
                if bits < MIN_TOKEN_BITS and key not in seen:
                    seen.add(key)
                    yield Finding(
                        vuln_type="auth-session",
                        title=f"Low-entropy session token ('{cname}')",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.TENTATIVE,
                        url=endpoint.url,
                        description=(
                            f"The session token '{cname}' has ~{bits:.0f} bits of entropy "
                            f"(< {MIN_TOKEN_BITS}), making it potentially predictable/brute-forceable."
                        ),
                        remediation=(
                            "Generate session tokens from a CSPRNG with >= 128 bits of entropy."
                        ),
                        cwe="CWE-331",
                        scanner=SCANNER_NAME,
                        evidence=Evidence(matched_at=cname, notes=f"~{bits:.0f} bits"),
                    )


__all__ = [
    "AuthSessionScanner",
    "cookie_issues",
    "shannon_entropy",
    "token_strength_bits",
    "is_session_cookie",
]
