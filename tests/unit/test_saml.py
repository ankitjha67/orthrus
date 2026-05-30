"""SAML response inspection: decode + signature/assertion/NameID analysis."""

from __future__ import annotations

import base64
import zlib
from types import SimpleNamespace

import pytest

from orthrus.core.schemas import Endpoint, HttpMethod, Param, ParamLocation, Severity
from orthrus.scanners.saml import _MAX_SAML_BYTES, SamlScanner, analyze_saml, decode_saml

pytest.importorskip("lxml")

_UNSIGNED = (
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
    '<saml:Assertion><saml:Subject><saml:NameID>alice@example.com</saml:NameID>'
    "</saml:Subject></saml:Assertion></samlp:Response>"
)
_SIGNED = (
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
    'xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
    "<saml:Assertion><ds:Signature>sig</ds:Signature>"
    "<saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject></saml:Assertion>"
    "</samlp:Response>"
)
_DOUBLE = _UNSIGNED.replace("</samlp:Response>", "<saml:Assertion/></samlp:Response>").replace(
    "<saml:Assertion>", '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">s</ds:Signature><saml:Assertion>', 1
)
_COMMENT = (
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
    'xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
    "<saml:Assertion><ds:Signature>s</ds:Signature><saml:Subject>"
    "<saml:NameID>admin<!--comment-->@evil.com</saml:NameID></saml:Subject>"
    "</saml:Assertion></samlp:Response>"
)


# ----------------------------------------------------------------- decode
def test_decode_plain_base64_xml():
    enc = base64.b64encode(_UNSIGNED.encode()).decode()
    assert decode_saml(enc).startswith("<samlp:Response")


def test_decode_garbage_returns_none():
    assert decode_saml("!!!not base64!!!") is None or decode_saml("aGVsbG8=") is None


def test_decode_legit_deflated_samlrequest_roundtrips():
    """A genuine raw-DEFLATE SAMLRequest (Redirect binding) still decodes."""
    co = zlib.compressobj(wbits=-15)  # raw DEFLATE, no zlib header
    deflated = co.compress(_UNSIGNED.encode()) + co.flush()
    enc = base64.b64encode(deflated).decode()
    assert decode_saml(enc).startswith("<samlp:Response")


def test_decode_refuses_decompression_bomb():
    """A tiny DEFLATE blob inflating past the cap is refused, not inflated."""
    bomb_plain = b"A" * (_MAX_SAML_BYTES + 1_000_000)  # > 10 MB inflated
    co = zlib.compressobj(wbits=-15)
    deflated = co.compress(bomb_plain) + co.flush()
    assert len(deflated) < 50_000  # a few KB on the wire...
    enc = base64.b64encode(deflated).decode()
    # ...must NOT inflate to 11 MB in memory — refused outright.
    assert decode_saml(enc) is None


def test_decode_refuses_oversized_base64_input():
    """An absurdly large encoded value is rejected before any base64 work."""
    assert decode_saml("A" * 2_000_000) is None


# ----------------------------------------------------------------- analyze
def test_unsigned_assertion_flagged():
    issues = analyze_saml(_UNSIGNED)
    assert any(i[0] == Severity.HIGH and "unsigned" in i[1].lower() for i in issues)


def test_signed_single_assertion_clean():
    assert analyze_saml(_SIGNED) == []


def test_multiple_assertions_flagged():
    issues = analyze_saml(_DOUBLE)
    assert any("signature-wrapping" in i[1].lower() for i in issues)


def test_nameid_comment_flagged():
    issues = analyze_saml(_COMMENT)
    assert any(i[3] == "CWE-290" for i in issues)


def test_xxe_safe_on_entity_doc():
    evil = '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><r>&e;</r>'
    # must not raise / must not resolve the entity
    assert analyze_saml(evil) == []


# ----------------------------------------------------------------- scan flow
async def test_scan_flags_unsigned_saml_response():
    enc = base64.b64encode(_UNSIGNED.encode()).decode()
    ep = Endpoint(
        url="https://sp/acs",
        method=HttpMethod.POST,
        params=[Param(name="SAMLResponse", location=ParamLocation.BODY, value=enc)],
    )
    ctx = SimpleNamespace(endpoints=[ep])
    findings = [f async for f in SamlScanner().scan(ctx)]
    assert any(f.vuln_type == "saml-misconfig" and f.severity == Severity.HIGH for f in findings)
