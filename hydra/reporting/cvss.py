"""CVSS v3.1 base-score engine and per-vulnerability default vectors (PRD §8.2).

Implements the CVSS v3.1 base-score formula (exploitability + impact + the
official Roundup) from a vector string, plus sensible default base vectors per
HYDRA vuln_type so findings without an explicit vector still get a score.
"""

from __future__ import annotations

import math

from hydra.core.schemas import Finding, Severity

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
    "security-headers": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "auth-session": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "tls": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
}


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
    "parse_vector",
    "severity_for_score",
    "assign_cvss",
    "DEFAULT_VECTORS",
]
