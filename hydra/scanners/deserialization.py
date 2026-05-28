"""Insecure deserialization scanner (PRD §6.8 Deserialization).

Passive: scans user-influenced values (query parameters, cookies) for the
signatures of serialized object formats. Presence of attacker-controllable
serialized data is a strong indicator of an insecure-deserialization surface;
actual gadget-chain exploitation is out of scope for detection.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from hydra.core.context import ScanContext
from hydra.core.schemas import Confidence, Evidence, Finding, Severity
from hydra.scanners.base_scanner import BaseScanner
from hydra.scanners.registry import register

SCANNER_NAME = "deserialization"

# format label -> compiled signature matcher over a (possibly base64) value.
_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("Java serialized object", re.compile(r"^rO0AB")),  # base64 of 0xAC 0xED 0x00 0x05
    ("Java serialized object", re.compile(r"\xac\xed\x00\x05")),  # raw stream header
    ("PHP serialized object", re.compile(r"^[aOs]:\d+:")),
    ("PHP serialized object", re.compile(r'O:\d+:"')),
    (".NET BinaryFormatter", re.compile(r"^AAEAAAD/////")),
    ("Python pickle", re.compile(r"^gA[ISQR]")),  # base64 of \x80\x02 / \x80\x04 ...
    ("Ruby Marshal", re.compile(r"^BAh")),  # base64 of \x04\x08
]

MIN_LEN = 8


def detect_serialized(value: str) -> str | None:
    """Return the serialized-format label if ``value`` matches a signature."""
    if not value or len(value) < MIN_LEN:
        return None
    for label, pattern in _SIGNATURES:
        if pattern.search(value):
            return label
    return None


@register
class DeserializationScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "deserialization"

    def _finding(self, url: str, where: str, value: str, fmt: str) -> Finding:
        preview = value[:48] + ("..." if len(value) > 48 else "")
        return Finding(
            vuln_type="deserialization",
            title=f"Serialized object in {where} ({fmt})",
            severity=Severity.MEDIUM,
            confidence=Confidence.TENTATIVE,
            url=url,
            parameter=where,
            description=(
                f"A {fmt} appears in a user-controllable {where}. If deserialized without "
                "integrity checks, this can lead to remote code execution via gadget chains."
            ),
            remediation=(
                "Avoid deserializing untrusted data. Use data-only formats (JSON) with strict "
                "schemas, sign/encrypt serialized state, and use allow-list type filters."
            ),
            cwe="CWE-502",
            scanner=SCANNER_NAME,
            evidence=Evidence(matched_at=preview, notes=f"{fmt} signature"),
        )

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen: set[tuple[str, str]] = set()
        for endpoint in ctx.endpoints:
            host = urlsplit(endpoint.url).netloc
            for param in endpoint.params:
                if not param.value:
                    continue
                fmt = detect_serialized(param.value)
                if fmt:
                    key = (host, f"param:{param.name}")
                    if key not in seen:
                        seen.add(key)
                        yield self._finding(endpoint.url, f"parameter '{param.name}'", param.value, fmt)
            for line in endpoint.set_cookies:
                if "=" not in line:
                    continue
                name, _, rest = line.split(";", 1)[0].partition("=")
                fmt = detect_serialized(rest)
                if fmt:
                    key = (host, f"cookie:{name.strip()}")
                    if key not in seen:
                        seen.add(key)
                        yield self._finding(endpoint.url, f"cookie '{name.strip()}'", rest, fmt)


__all__ = ["DeserializationScanner", "detect_serialized"]
