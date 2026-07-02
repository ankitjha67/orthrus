"""LDAP injection scanner (error-based).

Sends LDAP-filter-breaking payloads (unbalanced parentheses, stray backslash,
wildcard/operator fragments) into every injection point and flags responses that
leak an LDAP/directory error — the same low-false-positive, error-based approach
the SQLi and NoSQL scanners use. A baseline is checked first so endpoints that
error on *any* input are skipped.

Boolean auth-bypass injection (e.g. ``*)(uid=*))(|(uid=*``) is a natural
follow-up; this module ships the high-signal error-based detector first.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from orthrus.scanners._injection import injection_points, send, used_url
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register

SCANNER_NAME = "ldap-injection"
MAX_PROBES = 80

_BASELINE = "orthrusbaseline1"

# Payloads that break LDAP search-filter parsing (RFC 4515 metacharacters).
_PAYLOADS: tuple[str, ...] = (
    "*",
    ")",
    "(",
    "\\",
    "*)(uid=*",
    "*))%00",
)

# Substrings that mark an LDAP/directory-server error across common stacks.
_LDAP_ERRORS: tuple[str, ...] = (
    "javax.naming.directory",
    "javax.naming.namenotfoundexception",
    "ldapexception",
    "com.sun.jndi.ldap",
    "invalid dn syntax",
    "bad search filter",
    "supplied argument is not a valid ldap",
    "ldap_search",
    "ldap_bind",
    "object class violation",
    "openldap",
    "xmlrpc - lasso",  # Lasso LDAP connector
    "acceptsecuritycontext error",  # Active Directory bind failure
    "dsid-",  # Active Directory error code marker
    "protocol error in search filter",
    "unbalanced parenthesis",
)


def detect_ldap_error(body: str) -> bool:
    """True if the response body reveals an LDAP/directory-server error."""
    low = body.lower()
    return any(sig in low for sig in _LDAP_ERRORS)


@register
class LdapInjectionScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "ldap-injection"
    min_aggressiveness = Aggressiveness.NORMAL

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        probes = 0
        for point in injection_points(ctx):
            if probes >= MAX_PROBES:
                break
            probes += 1

            baseline = await send(ctx, point, _BASELINE)
            if baseline is not None and detect_ldap_error(baseline.text):
                continue  # endpoint errors on benign input -> not a reliable signal

            for payload in _PAYLOADS:
                resp = await send(ctx, point, payload)
                if resp is None or not detect_ldap_error(resp.text):
                    continue
                yield Finding(
                    vuln_type="ldap-injection",
                    title=f"LDAP injection (error-based) in '{point.param}'",
                    severity=Severity.HIGH,
                    confidence=Confidence.FIRM,
                    url=used_url(point, payload),
                    parameter=point.param,
                    param_location=point.location,
                    description=(
                        f"The parameter '{point.param}' reflected an LDAP/directory error when "
                        "sent a filter-breaking payload. This indicates user input is concatenated "
                        "into an LDAP search filter, enabling authentication bypass, authorization "
                        "filter tampering, and directory data exfiltration via wildcard/operator "
                        "injection."
                    ),
                    remediation=(
                        "Escape LDAP filter metacharacters per RFC 4515 (\\28 \\29 \\2a \\5c \\00) "
                        "using the platform's encoding API, validate input against an allow-list, "
                        "and bind with least-privilege service accounts."
                    ),
                    cwe="CWE-90",
                    scanner=SCANNER_NAME,
                    evidence=Evidence(
                        request_raw=f"{point.param}={payload}",
                        notes="LDAP directory error reflected in response",
                    ),
                )
                break


__all__ = ["LdapInjectionScanner", "detect_ldap_error"]
