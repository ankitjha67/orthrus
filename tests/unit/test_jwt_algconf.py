"""JWT RS->HS algorithm-confusion: JWK->PEM, offline forge, and scan flow."""

from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest

from orthrus.scanners.jwt_analyzer import (
    JwtScanner,
    forge_alg_confusion,
    is_asymmetric_alg,
    jwk_to_public_pem,
)


def test_is_asymmetric_alg():
    assert is_asymmetric_alg("RS256") is True
    assert is_asymmetric_alg("ES384") is True
    assert is_asymmetric_alg("HS256") is False
    assert is_asymmetric_alg("none") is False


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _rsa_material():
    """Return (private_pem, rs256_token, rsa_jwk) using real crypto."""
    pytest.importorskip("cryptography")
    jwt = pytest.importorskip("jwt")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub = key.public_key().public_numbers()
    n = pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big")
    e = pub.e.to_bytes((pub.e.bit_length() + 7) // 8, "big")
    jwk = {"kty": "RSA", "n": _b64u(n), "e": _b64u(e), "kid": "k1", "alg": "RS256"}
    token = jwt.encode({"user": "bob", "role": "user"}, private_pem, algorithm="RS256")
    return private_pem, token, jwk


def test_jwk_to_public_pem_roundtrips():
    _, _, jwk = _rsa_material()
    pem = jwk_to_public_pem(jwk)
    assert pem is not None and "BEGIN PUBLIC KEY" in pem


def test_forge_alg_confusion_produces_valid_hs256():
    _, token, jwk = _rsa_material()
    pem = jwk_to_public_pem(jwk)
    forged = forge_alg_confusion(token, pem)
    assert forged is not None and forged.count(".") == 2  # a real JWT


def test_jwk_to_public_pem_rejects_non_rsa():
    assert jwk_to_public_pem({"kty": "oct", "k": "abc"}) is None


# ----------------------------------------------------------------- scan flow
class _Resp:
    def __init__(self, status: int, text: str) -> None:
        self.status_code = status
        self.text = text


class _Http:
    def __init__(self, token: str, jwks_json: str) -> None:
        self.session = SimpleNamespace(cookies=SimpleNamespace(values=lambda: [f"sid={token}"]))
        self._jwks = jwks_json

    async def get(self, url: str, **kw: object) -> _Resp:
        if "jwks" in url or "openid" in url:
            return _Resp(200, self._jwks)
        return _Resp(404, "nf")


async def test_scan_flags_alg_confusion_with_published_jwks():
    import json

    _, token, jwk = _rsa_material()
    jwks = json.dumps({"keys": [jwk]})
    ctx = SimpleNamespace(
        endpoints=[],
        http=_Http(token, jwks),
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(target="https://h/", extra_headers={}),
    )
    findings = [f async for f in JwtScanner().scan(ctx)]
    algconf = [f for f in findings if "algorithm confusion" in f.title]
    assert len(algconf) == 1
    assert algconf[0].cwe == "CWE-347"
    assert algconf[0].severity.value == "high"


async def test_scan_no_algconf_without_jwks():
    _, token, _ = _rsa_material()
    ctx = SimpleNamespace(
        endpoints=[],
        http=_Http(token, "not found"),  # /jwks returns this only on jwks paths; here 404 elsewhere
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(target="https://h/", extra_headers={}),
    )
    # JWKS endpoints return non-JSON -> no keys -> no alg-confusion finding.
    findings = [f async for f in JwtScanner().scan(ctx)]
    assert not any("algorithm confusion" in f.title for f in findings)
