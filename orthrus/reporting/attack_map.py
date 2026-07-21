"""MITRE ATT&CK (+ minimal D3FEND) technique mapping and ATT&CK Navigator export.

Maps each ORTHRUS ``vuln_type`` to the MITRE ATT&CK Enterprise techniques the
weakness enables, so a report/finding carries the adversary techniques a SOC
already tracks - and produces a **MITRE ATT&CK Navigator layer** so a scan can be
visualized directly on the ATT&CK matrix (heat-mapped by finding count).

The technique selection was informed by the community
``Anthropic-Cybersecurity-Skills`` catalogue (github.com/mukul975/Anthropic-
Cybersecurity-Skills, Apache-2.0), whose web-app skills carry per-technique
``mitre_attack`` frontmatter; the IDs themselves are public MITRE facts. D3FEND
coverage in that source is sparse, so only the two countermeasures we can state
with confidence (D3-MFA, D3-ITF) are included rather than fabricated IDs.

Pure and deterministic: no I/O.
"""

from __future__ import annotations

from typing import Any

_ATTACK_URL = "https://attack.mitre.org/techniques/"

# Canonical technique names (MITRE ATT&CK Enterprise; AML.* is MITRE ATLAS).
_NAMES: dict[str, str] = {
    "T1190": "Exploit Public-Facing Application",
    "T1059": "Command and Scripting Interpreter",
    "T1059.007": "Command and Scripting Interpreter: JavaScript",
    "T1078": "Valid Accounts",
    "T1110": "Brute Force",
    "T1550": "Use Alternate Authentication Material",
    "T1552": "Unsecured Credentials",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1213": "Data from Information Repositories",
    "T1083": "File and Directory Discovery",
    "T1005": "Data from Local System",
    "T1040": "Network Sniffing",
    "T1557": "Adversary-in-the-Middle",
    "T1090": "Proxy",
    "T1046": "Network Service Scanning",
    "T1195.001": "Supply Chain Compromise: Software Dependencies",
    "T1584.001": "Compromise Infrastructure: Domains",
    "T1499": "Endpoint Denial of Service",
    "T1068": "Exploitation for Privilege Escalation",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1539": "Steal Web Session Cookie",
    "T1189": "Drive-by Compromise",
    "T1187": "Forced Authentication",
    "T1505.003": "Server Software Component: Web Shell",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1606": "Forge Web Credentials",
    "T1204": "User Execution",
    "T1071": "Application Layer Protocol",
    "AML.T0051": "LLM Prompt Injection (ATLAS)",
}

# vuln_type → ATT&CK technique IDs (scanner-specific variants normalized below).
_ATTACK: dict[str, list[str]] = {
    "sqli": ["T1190", "T1059", "T1005"],
    "graphql-injection": ["T1190", "T1059", "T1005"],
    "nosql-injection": ["T1190", "T1059"],
    "ldap-injection": ["T1190"],
    "xpath-injection": ["T1190", "T1083"],
    "cmd-injection": ["T1190", "T1059"],
    "ssti": ["T1190", "T1059"],
    "lfi": ["T1190", "T1083", "T1005"],
    "xxe": ["T1190", "T1083", "T1005"],
    "ssrf": ["T1190", "T1090"],
    "xss": ["T1059.007", "T1539", "T1189"],
    "deserialization": ["T1190", "T1059"],
    "default-credentials": ["T1078", "T1110"],
    "jwt": ["T1550", "T1552"],
    "oauth-flow": ["T1550", "T1078"],
    "saml": ["T1550", "T1606"],
    "auth-session": ["T1078", "T1539"],
    "idor": ["T1190", "T1083", "T1213"],
    "broken-authorization": ["T1190", "T1213"],
    "privilege-escalation": ["T1068", "T1548"],
    "mass-assignment": ["T1190"],
    "business-logic": ["T1190"],
    "cve": ["T1190"],
    "product-cve": ["T1190"],
    "exposed-file": ["T1083", "T1213"],
    "directory-listing": ["T1083", "T1213"],
    "framework-debug": ["T1190", "T1213"],
    "exposed-secret": ["T1552", "T1552.001"],
    "secret-exposure": ["T1552", "T1552.001"],
    "tls": ["T1040", "T1557"],
    "mixed-content": ["T1557"],
    "dependency-confusion": ["T1195.001"],
    "sca-js-libraries": ["T1195.001"],
    "cors": ["T1539"],
    "csrf": ["T1190", "T1539"],
    "open-redirect": ["T1566.002", "T1204"],
    "crlf-injection": ["T1190"],
    "host-header-injection": ["T1190", "T1187"],
    "request-smuggling": ["T1190", "T1071"],
    "cache-poisoning": ["T1190", "T1557"],
    "web-cache-deception": ["T1190", "T1539"],
    "prototype-pollution": ["T1190", "T1059.007"],
    "sspp": ["T1190", "T1059"],
    "graphql": ["T1190", "T1213"],
    "websocket": ["T1190"],
    "subdomain-takeover": ["T1584.001"],
    "file-upload": ["T1190", "T1505.003"],
    "grpc-reflection": ["T1190", "T1046"],
    "exposed-services": ["T1190", "T1046"],
    "shadow-api": ["T1190", "T1213"],
    "api-misconfig": ["T1190"],
    "csv-injection": ["T1204", "T1059"],
    "prompt-injection": ["AML.T0051"],
    "llm-prompt-injection": ["AML.T0051"],
    "race-condition": ["T1190"],
}
_ATTACK_ALIASES = {
    "reflected-xss": "xss", "dom-xss": "xss", "stored-xss": "xss", "dom-taint": "xss",
    "command-injection": "cmd-injection", "os-command-injection": "cmd-injection",
    "path-traversal": "lfi", "bola": "idor", "bfla": "broken-authorization",
    "llm-info-disclosure": "prompt-injection", "graphql-dos": "graphql",
    "server-side-prototype-pollution": "sspp",
}
_DEFAULT = ["T1190"]

# Minimal, confident D3FEND countermeasures (the source catalogue barely populates
# D3FEND, so we only assert the two we can state correctly).
_D3FEND_MFA = ("D3-MFA", "Multi-factor Authentication")
_D3FEND_ITF = ("D3-ITF", "Inbound Traffic Filtering")
_D3FEND_AUTH = {"jwt", "oauth-flow", "saml", "auth-session", "default-credentials"}
_D3FEND_INJECTION = {
    "sqli", "nosql-injection", "ldap-injection", "xpath-injection", "cmd-injection",
    "ssti", "xxe", "ssrf", "deserialization", "crlf-injection", "request-smuggling",
    "xss", "prototype-pollution", "sspp",
}


def _canon(vuln_type: str) -> str:
    return _ATTACK_ALIASES.get(vuln_type, vuln_type)


def attack_ids(vuln_type: str) -> list[str]:
    """ATT&CK technique IDs for a vuln type (never empty)."""
    return _ATTACK.get(_canon(vuln_type), _DEFAULT)


def attack_for(vuln_type: str) -> list[dict[str, str]]:
    """Structured ATT&CK techniques: [{id, name, url}] for the report."""
    return [
        {"id": tid, "name": _NAMES.get(tid, tid), "url": _ATTACK_URL + tid.replace(".", "/")}
        for tid in attack_ids(vuln_type)
    ]


def d3fend_for(vuln_type: str) -> list[dict[str, str]]:
    """Structured D3FEND countermeasures (minimal, confident set)."""
    vt = _canon(vuln_type)
    out: list[dict[str, str]] = []
    if vt in _D3FEND_AUTH:
        out.append({"id": _D3FEND_MFA[0], "name": _D3FEND_MFA[1]})
    if vt in _D3FEND_INJECTION:
        out.append({"id": _D3FEND_ITF[0], "name": _D3FEND_ITF[1]})
    return out


def _sev_rank(sev: object) -> int:
    s = getattr(sev, "value", sev)
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(s or "info", 0)


def build_navigator_layer(findings: list, *, name: str = "ORTHRUS findings") -> dict[str, Any]:
    """Build a MITRE ATT&CK Navigator layer (v4.5) heat-mapping enterprise techniques
    by the number of findings that map to each. ATLAS (AML.*) techniques are excluded
    - they belong to the ATLAS matrix, not enterprise-attack.
    """
    counts: dict[str, int] = {}
    types: dict[str, set[str]] = {}
    for f in findings:
        vt = (f.get("vuln_type") if isinstance(f, dict) else getattr(f, "vuln_type", "")) or ""
        for tid in attack_ids(vt):
            if tid.startswith("AML."):
                continue
            counts[tid] = counts.get(tid, 0) + 1
            types.setdefault(tid, set()).add(vt)
    techniques = [
        {
            "techniqueID": tid,
            "score": n,
            "comment": f"{', '.join(sorted(types[tid]))} ({n} finding{'s' if n != 1 else ''})",
            "enabled": True,
        }
        for tid, n in sorted(counts.items())
    ]
    max_score = max(counts.values(), default=1)
    return {
        "name": name,
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "ORTHRUS scan findings mapped to MITRE ATT&CK (score = finding count).",
        "techniques": techniques,
        "gradient": {"colors": ["#ffe766", "#ff6666"], "minValue": 0, "maxValue": max_score},
        "legendItems": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "sorting": 3,
    }


__all__ = ["attack_ids", "attack_for", "d3fend_for", "build_navigator_layer"]
