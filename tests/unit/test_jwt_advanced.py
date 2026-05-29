"""Advanced JWT header-attack detection (jku/x5u key injection, kid injection)."""

from __future__ import annotations

import base64
import json

import pytest

from orthrus.core.schemas import Severity
from orthrus.scanners.jwt_analyzer import analyze_jwt

jwt = pytest.importorskip("jwt")  # pyjwt ships in the [scanners] extra


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _token(header: dict, payload: dict | None = None) -> str:
    return ".".join([_b64(header), _b64(payload or {"user": "admin"}), "AAAA"])


def test_detects_jku_key_url() -> None:
    tok = _token({"alg": "RS256", "typ": "JWT", "jku": "https://evil.example/jwks.json"})
    titles = [t for _s, t, _d, _c in analyze_jwt(tok)]
    assert any("external key URL" in t and "jku" in t for t in titles)
    assert any(s == Severity.HIGH for s, t, _d, _c in analyze_jwt(tok) if "jku" in t)


def test_detects_x5u_key_url() -> None:
    tok = _token({"alg": "RS256", "x5u": "https://evil.example/cert.pem"})
    assert any("x5u" in t for _s, t, _d, _c in analyze_jwt(tok))


def test_detects_kid_path_traversal() -> None:
    tok = _token({"alg": "HS256", "kid": "../../../../dev/null"})
    issues = analyze_jwt(tok)
    assert any("kid" in t and s == Severity.MEDIUM for s, t, _d, _c in issues)


def test_clean_token_has_no_header_attack_findings() -> None:
    tok = _token({"alg": "HS256", "kid": "key-2024-01"})
    titles = [t for _s, t, _d, _c in analyze_jwt(tok)]
    assert not any("external key URL" in t for t in titles)
    assert not any("injection metacharacters" in t for t in titles)
