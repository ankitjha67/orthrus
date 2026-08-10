"""CWE -> HackerOne "Weakness" mapping + honest coverage accounting.

The HackerOne "Weakness" field is the full CWE + CAPEC dictionary (~1,500 entries) -
a taxonomy for *labelling* a report, not a checklist a scanner detects. The vast
majority (memory-safety, hardware/firmware, network, Bluetooth, mobile-internal,
physical/social) is structurally invisible to a black-box web/API DAST and is out of
scope for ORTHRUS by design.

This maps the CWEs ORTHRUS actually emits to the readable weakness label the operator
picks in the dropdown (so submission is one click), and records the categories that are
deliberately not covered so the tool is honest about what "no findings" means.
"""

from __future__ import annotations

# CWE -> the HackerOne weakness label (dropdown shows "Name (cwe-NN)").
# Only the CWEs ORTHRUS's scanners/confirmers actually produce are listed.
WEAKNESS_LABELS: dict[str, str] = {
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-78": "OS Command Injection",
    "CWE-94": "Code Injection",
    "CWE-74": "Improper Neutralization of Special Elements (Injection)",
    "CWE-90": "LDAP Injection",
    "CWE-643": "XPath Injection",
    "CWE-1336": "Server-Side Template Injection (SSTI)",
    "CWE-943": "NoSQL Injection",
    "CWE-22": "Path Traversal",
    "CWE-235": "Improper Handling of Extra Parameters (HTTP Parameter Pollution)",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-601": "Open Redirect",
    "CWE-113": "HTTP Response Splitting",
    "CWE-444": "HTTP Request Smuggling",
    "CWE-644": "Improper Neutralization of HTTP Headers",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-1321": "Prototype Pollution",
    "CWE-915": "Mass Assignment",
    "CWE-472": "External Control of Assumed-Immutable Web Parameter",
    "CWE-639": "Insecure Direct Object Reference (IDOR)",
    "CWE-640": "Weak Password Recovery Mechanism",
    "CWE-285": "Improper Authorization",
    "CWE-290": "Authentication Bypass by Spoofing",
    "CWE-347": "Improper Verification of Cryptographic Signature (JWT)",
    "CWE-384": "Session Fixation",
    "CWE-603": "Use of Client-Side Authentication",
    "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
    "CWE-799": "Improper Control of Interaction Frequency (No Rate Limiting)",
    "CWE-204": "Observable Response Discrepancy (User Enumeration)",
    "CWE-1392": "Use of Default Credentials",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-362": "Race Condition",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-674": "Uncontrolled Recursion",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-942": "Permissive Cross-domain Policy (CORS Misconfiguration)",
    "CWE-1385": "Missing Origin Validation in WebSockets",
    "CWE-1427": "Improper Neutralization of Input Used for LLM Prompting",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-209": "Generation of Error Message Containing Sensitive Information",
    "CWE-538": "Insertion of Sensitive Information into Externally-Accessible File",
    "CWE-548": "Exposure of Information Through Directory Listing",
    "CWE-525": "Use of Web Browser Cache Containing Sensitive Information",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
    "CWE-353": "Missing Support for Integrity Check",
    "CWE-350": "Reliance on Reverse DNS Resolution for a Security Decision",
    "CWE-16": "Configuration",
    "CWE-489": "Active Debug Code",
    "CWE-693": "Protection Mechanism Failure (Missing Security Header)",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-331": "Insufficient Entropy",
    "CWE-1236": "Improper Neutralization of Formula Elements in a CSV File",
    "CWE-1035": "Using Components with Known Vulnerabilities",
}

# Whole CWE/CAPEC families a black-box web/API DAST cannot observe over HTTP. Documented
# so "0 findings" is honest: these need source/binary analysis, a device, or other tools.
OUT_OF_SCOPE: dict[str, str] = {
    "Memory safety": "buffer overflow/underflow/over-read, use-after-free, uninitialized "
                     "pointers - need source/binary analysis or native fuzzing.",
    "Hardware / firmware": "BIOS/ASIC/firmware tampering, hardware sentinels - a different "
                           "domain entirely.",
    "Network / protocol": "BGP disabling, Blue Boxing, amplification at the link layer - "
                          "not HTTP-observable.",
    "Wireless": "Bluetooth impersonation, RF attacks - out of a web scanner's reach.",
    "Mobile-internal": "Android activity/intent hijack, thick-client internals - need the "
                       "APK and a device (see the mobile methodology).",
    "Physical / social / process": "malicious shared webroot, altered software updates, "
                                    "social engineering - human/process, not automatable here.",
}


def weakness_label(cwe: str | None) -> str:
    """The dropdown-style label for a CWE, e.g. ``Cross-site Scripting (XSS) (cwe-79)``.

    Falls back to the bare CWE id for anything not in the map (still a valid selection).
    """
    if not cwe:
        return "n/a"
    label = WEAKNESS_LABELS.get(cwe.upper())
    return f"{label} ({cwe.lower()})" if label else cwe


def covered_cwes() -> list[str]:
    return sorted(WEAKNESS_LABELS, key=lambda c: int(c.split("-")[1]))


__all__ = ["WEAKNESS_LABELS", "OUT_OF_SCOPE", "weakness_label", "covered_cwes"]
