"""Authentication & session cookie security scanner (PRD §6.6).

Foundation scope: passive analysis of Set-Cookie security attributes
(Secure / HttpOnly / SameSite). Default-credential testing, session-token
entropy, and reset-flow analysis are later additions to this module.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from hydra.core.context import ScanContext
from hydra.core.schemas import Confidence, Evidence, Finding, Severity
from hydra.scanners.base_scanner import BaseScanner
from hydra.scanners.registry import register

SCANNER_NAME = "auth-session"


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


__all__ = ["AuthSessionScanner", "cookie_issues"]
