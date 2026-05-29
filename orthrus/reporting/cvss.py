"""CVSS v3.1 base-score engine and per-vulnerability default vectors (PRD §8.2).

Implements the CVSS v3.1 base-score formula (exploitability + impact + the
official Roundup) from a vector string, plus sensible default base vectors per
ORTHRUS vuln_type so findings without an explicit vector still get a score.
"""

from __future__ import annotations

import math

from orthrus.core.schemas import Finding, Severity

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}


def parse_vector(vector: str) -> dict[str, str]:
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" in part and not part.startswith("CVSS"):
            key, _, val = part.partition(":")
            metrics[key] = val
    return metrics


def _roundup(value: float) -> float:
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def base_score(vector: str) -> float:
    m = parse_vector(vector)
    try:
        scope_changed = m["S"] == "C"
        av = _AV[m["AV"]]
        ac = _AC[m["AC"]]
        pr = (_PR_C if scope_changed else _PR_U)[m["PR"]]
        ui = _UI[m["UI"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError:
        return 0.0

    isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    raw = (1.08 * (impact + exploitability)) if scope_changed else (impact + exploitability)
    return _roundup(min(raw, 10.0))


def severity_for_score(score: float) -> Severity:
    if score == 0:
        return Severity.INFO
    if score < 4.0:
        return Severity.LOW
    if score < 7.0:
        return Severity.MEDIUM
    if score < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL


# Default base vectors per vuln_type (used when a scanner did not supply one).
DEFAULT_VECTORS: dict[str, str] = {
    "sqli": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cmd-injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "ssti": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "deserialization": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "jwt": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "ssrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "lfi": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "xxe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "prototype-pollution": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L",
    "xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "idor": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "csrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
    "cors": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "open-redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
    "cache-poisoning": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
    "graphql": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "exposed-file": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "websocket": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "default-creds": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "race-condition": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
    "example": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "security-headers": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "auth-session": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "tls": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "parameter-tampering": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    "parameter-pollution": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "host-header-injection": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "framework-debug": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "vulnerable-component": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "web-cache-deception": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "nosql-injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "subdomain-takeover": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
}


def _v3_to_v4_vector(v3_vector: str) -> str:
    """Build a CVSS:4.0 base vector from a v3.1 vector (metric remap)."""
    m = parse_vector(v3_vector)
    subseq = "L" if m.get("S") == "C" else "N"
    return (
        "CVSS:4.0"
        f"/AV:{m.get('AV', 'N')}/AC:{m.get('AC', 'L')}/AT:N"
        f"/PR:{m.get('PR', 'N')}/UI:{m.get('UI', 'N')}"
        f"/VC:{m.get('C', 'N')}/VI:{m.get('I', 'N')}/VA:{m.get('A', 'N')}"
        f"/SC:{subseq}/SI:{subseq}/SA:{subseq}"
    )


def base_score_v4(vector: str) -> float:
    """Approximate CVSS v4.0 base score.

    Maps v4.0 metrics back onto the v3.1 formula as a documented approximation —
    the official CVSS-B v4.0 MacroVector lookup tables are not implemented. The
    v4.0 *vector* is exact; this numeric is an estimate (v3.1 stays authoritative).
    """
    m = parse_vector(vector)
    if "VC" not in m:
        return base_score(vector)
    subseq_changed = any(m.get(x, "N") != "N" for x in ("SC", "SI", "SA"))
    v3_equiv = (
        "CVSS:3.1"
        f"/AV:{m.get('AV', 'N')}/AC:{m.get('AC', 'L')}"
        f"/PR:{m.get('PR', 'N')}/UI:{m.get('UI', 'N')}"
        f"/S:{'C' if subseq_changed else 'U'}"
        f"/C:{m.get('VC', 'N')}/I:{m.get('VI', 'N')}/A:{m.get('VA', 'N')}"
    )
    return base_score(v3_equiv)


DEFAULT_VECTORS_V4: dict[str, str] = {
    vuln_type: _v3_to_v4_vector(vector) for vuln_type, vector in DEFAULT_VECTORS.items()
}


def v4_for(vuln_type: str) -> tuple[str | None, float | None]:
    vector = DEFAULT_VECTORS_V4.get(vuln_type)
    return (vector, base_score_v4(vector)) if vector else (None, None)


def assign_cvss(finding: Finding) -> Finding:
    """Populate cvss_vector/score on a finding from defaults if missing."""
    if finding.cvss_score is not None and finding.cvss_vector:
        return finding
    if finding.cvss_vector:
        finding.cvss_score = base_score(finding.cvss_vector)
        return finding
    vector = DEFAULT_VECTORS.get(finding.vuln_type)
    if vector:
        finding.cvss_vector = vector
        finding.cvss_score = base_score(vector)
    return finding


__all__ = [
    "base_score",
    "base_score_v4",
    "parse_vector",
    "severity_for_score",
    "assign_cvss",
    "v4_for",
    "DEFAULT_VECTORS",
    "DEFAULT_VECTORS_V4",
]
