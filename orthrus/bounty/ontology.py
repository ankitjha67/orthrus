"""Versioned vulnerability-class ontology (PRD Appendix B).

ORTHRUS already maps findings to CWE / OWASP / ATT&CK (in the report generator).
This module adds the two *governance* attributes those maps don't carry, keyed by
the scanner ``vuln_type``:

* ``confidence_ceiling`` — the highest confidence a class can honestly reach.
  Most classes can be actively re-proven (``confirmed``); a few have no safe,
  generic active proof (business logic, races) and top out at ``firm``.
* ``destructive`` — whether confirming/abusing the class writes state or can
  affect other users, so it warrants manual verification before active testing.

The ontology is versioned (semver) and extensible; unknown types get a safe
default (``confirmed`` ceiling, non-destructive) so new scanners still work.
"""

from __future__ import annotations

from dataclasses import dataclass

ONTOLOGY_VERSION = "1.0.0"

# Appendix-B category per vuln_type (grouping only; CWE/OWASP live in the generator).
_CATEGORY = {
    "sqli": "injection", "nosql-injection": "injection", "ldap": "injection",
    "xpath": "injection", "ssti": "injection", "cmd-injection": "injection",
    "lfi": "injection", "xxe": "injection", "crlf-injection": "injection",
    "csv-injection": "injection", "graphql-injection": "injection",
    "xss": "xss", "reflected-xss": "xss", "dom-xss": "xss", "stored-xss": "xss",
    "idor": "access-logic", "csrf": "access-logic", "open-redirect": "access-logic",
    "host-header-injection": "access-logic", "race-condition": "access-logic",
    "business-logic": "access-logic", "parameter-pollution": "access-logic",
    "jwt": "auth", "oauth-flow": "auth", "saml": "auth", "auth-session": "auth",
    "default-credentials": "auth",
    "ssrf": "server-side", "deserialization": "server-side",
    "prototype-pollution": "server-side", "sspp": "server-side",
    "security-headers": "config-transport", "cors": "config-transport",
    "tls": "config-transport", "clickjacking": "config-transport",
    "cache-poisoning": "config-transport", "web-cache-deception": "config-transport",
    "exposed-file": "config-transport", "file-upload": "config-transport",
    "request-smuggling": "config-transport", "directory-listing": "config-transport",
    "graphql": "protocol", "websocket": "protocol",
    "secret-exposure": "secrets", "sca-js-libraries": "supply-chain",
    "cve": "supply-chain", "product-cve": "supply-chain", "subdomain-takeout": "supply-chain",
    "mass-assignment": "access-logic", "llm-prompt-injection": "llm-ai",
}

# No safe, generic *active* proof exists → honestly caps at firm.
_CEILING_FIRM = {"business-logic", "race-condition"}

# Confirming/abusing writes state or can affect other users → verify manually.
_DESTRUCTIVE = {
    "mass-assignment", "file-upload", "race-condition", "business-logic",
    "stored-xss", "cache-poisoning", "web-cache-deception",
}


@dataclass(frozen=True)
class ClassInfo:
    vuln_type: str
    category: str
    confidence_ceiling: str   # 'confirmed' | 'firm'
    destructive: bool


def class_info(vuln_type: str) -> ClassInfo:
    vt = (vuln_type or "").lower()
    return ClassInfo(
        vuln_type=vt,
        category=_CATEGORY.get(vt, "other"),
        confidence_ceiling="firm" if vt in _CEILING_FIRM else "confirmed",
        destructive=vt in _DESTRUCTIVE,
    )


def is_destructive(vuln_type: str) -> bool:
    return (vuln_type or "").lower() in _DESTRUCTIVE


def confidence_ceiling(vuln_type: str) -> str:
    return "firm" if (vuln_type or "").lower() in _CEILING_FIRM else "confirmed"


__all__ = ["ONTOLOGY_VERSION", "ClassInfo", "class_info", "is_destructive", "confidence_ceiling"]
