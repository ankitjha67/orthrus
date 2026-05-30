"""SAML response inspection scanner (signature wrapping / unsigned assertions).

SAML single sign-on is a perennial source of authentication-bypass bugs. When an
SP accepts a ``SAMLResponse`` without strictly validating the signature, an
attacker can forge or wrap assertions and authenticate as anyone. This scanner
inspects any ``SAMLResponse`` it observes (in discovered endpoint parameters /
forms) and flags the classic weaknesses — all from offline XML analysis:

* **Unsigned assertion** — the response/assertion carries no XML-DSig
  ``<Signature>``; the assertion can be forged wholesale (CWE-347, HIGH).
* **Signature-wrapping surface (XSW)** — more than one ``<Assertion>`` (or
  multiple ``<Response>``/``<Signature>``) is present, the precondition for an
  XML Signature Wrapping attack that smuggles an attacker assertion past a
  signature that covers a different one (CWE-347, MEDIUM).
* **NameID comment truncation** — the ``<NameID>`` contains an XML comment,
  which some parsers truncate to escalate to another user's identity
  (CVE-2018-0489 class, CWE-290, MEDIUM).

The XML is parsed with entities/DTD/network disabled, so analysing an untrusted
SAML blob can never trigger XXE.
"""

from __future__ import annotations

import base64
import binascii
import zlib
from collections.abc import AsyncIterator

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger

try:
    from lxml import etree
except ImportError:  # lxml ships in the core deps
    etree = None  # type: ignore[assignment]

logger = get_logger("scanner.saml")

SCANNER_NAME = "saml"
MAX_RESPONSES = 10

# Decompression-bomb guards: a few hundred bytes of DEFLATE can inflate to
# gigabytes. A SAMLRequest is attacker-influenced (it arrives in a URL parameter
# or form field we observed), so analysing one must never be able to exhaust the
# scanner's memory. Bound both the encoded input and the inflated output.
_MAX_SAML_B64 = 1_000_000  # 1 MB of base64 in one param is already absurd for SAML
_MAX_SAML_BYTES = 10_000_000  # 10 MB hard ceiling on inflated XML


def _bounded_inflate(raw: bytes, wbits: int) -> str | None:
    """raw-DEFLATE inflate with a hard output cap (decompression-bomb safe).

    Returns the decoded text, or ``None`` if the data is not valid for this
    ``wbits`` *or* its output would exceed the cap (treated as a bomb and
    refused rather than truncated, so a partial bomb can't masquerade as XML).
    """
    try:
        dec = zlib.decompressobj(wbits)
        out = dec.decompress(raw, _MAX_SAML_BYTES)
    except zlib.error:
        return None
    if dec.unconsumed_tail:  # output hit the cap with input left → bomb, refuse
        return None
    return out.decode("utf-8", "replace")

_SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
_PROTO_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
_DS_NS = "http://www.w3.org/2000/09/xmldsig#"


def decode_saml(value: str) -> str | None:
    """Base64-decode a SAML message (also handling raw-deflated SAMLRequest)."""
    if not value or len(value) > _MAX_SAML_B64:
        return None
    try:
        raw = base64.b64decode(value, validate=False)
    except (binascii.Error, ValueError):
        return None
    if raw[:1] == b"<":
        return raw.decode("utf-8", "replace")
    # SAMLRequest in the Redirect binding is raw-DEFLATE compressed. Inflate with
    # a hard output cap so a decompression bomb can't exhaust memory.
    for wbits in (-15, 15):
        text = _bounded_inflate(raw, wbits)
        if text is not None:
            return text
    text = raw.decode("utf-8", "replace")
    return text if "<" in text else None


def _safe_parse(xml: str):
    if etree is None:
        return None
    parser = etree.XMLParser(
        resolve_entities=False, no_network=True, load_dtd=False, dtd_validation=False
    )
    try:
        return etree.fromstring(xml.encode("utf-8"), parser)
    except Exception:
        return None


def analyze_saml(xml: str) -> list[tuple[Severity, str, str, str]]:
    """Return (severity, title, detail, cwe) for SAML weaknesses in the document."""
    root = _safe_parse(xml)
    if root is None:
        return []
    issues: list[tuple[Severity, str, str, str]] = []
    assertions = root.findall(f".//{{{_SAML_NS}}}Assertion")
    signatures = root.findall(f".//{{{_DS_NS}}}Signature")
    if not assertions and root.tag.endswith("}Assertion"):
        assertions = [root]

    if assertions and not signatures:
        issues.append((
            Severity.HIGH,
            "SAML assertion is unsigned",
            "The SAML response/assertion carries no XML-DSig signature. If the service provider "
            "accepts it, an attacker can forge an assertion and authenticate as any user.",
            "CWE-347",
        ))
    if len(assertions) > 1 or len(root.findall(f".//{{{_PROTO_NS}}}Response")) > 1:
        issues.append((
            Severity.MEDIUM,
            "SAML response contains multiple assertions (signature-wrapping surface)",
            "More than one assertion/response element is present — the precondition for an XML "
            "Signature Wrapping (XSW) attack that smuggles an unsigned attacker assertion past a "
            "signature covering a different element.",
            "CWE-347",
        ))
    for name_id in root.findall(f".//{{{_SAML_NS}}}NameID"):
        if etree is not None and b"<!--" in etree.tostring(name_id):
            issues.append((
                Severity.MEDIUM,
                "SAML NameID contains an XML comment (truncation attack)",
                "The NameID contains an XML comment; parsers that mishandle comment nodes can "
                "truncate the value to impersonate another user (CVE-2018-0489 class).",
                "CWE-290",
            ))
            break
    return issues


@register
class SamlScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "saml-misconfig"

    def _saml_responses(self, ctx: ScanContext) -> list[tuple[str, str]]:
        """Collect (endpoint_url, SAMLResponse value) pairs from discovered params."""
        out: list[tuple[str, str]] = []
        seen: set[str] = set()
        for ep in ctx.endpoints:
            for param in ep.params:
                if param.name.lower() == "samlresponse" and param.value:
                    key = param.value[:40]
                    if key not in seen:
                        seen.add(key)
                        out.append((ep.url, param.value))
        return out[:MAX_RESPONSES]

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        if etree is None:
            return
        for url, value in self._saml_responses(ctx):
            xml = decode_saml(value)
            if xml is None:
                continue
            for severity, title, detail, cwe in analyze_saml(xml):
                yield Finding(
                    vuln_type="saml-misconfig",
                    title=title,
                    severity=severity,
                    confidence=Confidence.FIRM,
                    url=url,
                    description=detail,
                    remediation=(
                        "Validate the SAML signature strictly: require a signature over the "
                        "assertion, verify it against a pinned IdP certificate before reading any "
                        "claim, reject multiple/unsigned assertions, and canonicalise NameID "
                        "(strip comments). Use a vetted SAML library, not hand-rolled validation."
                    ),
                    cwe=cwe,
                    scanner=SCANNER_NAME,
                    evidence=Evidence(matched_at=title, notes="SAML response analysis"),
                )


__all__ = ["SamlScanner", "decode_saml", "analyze_saml"]
