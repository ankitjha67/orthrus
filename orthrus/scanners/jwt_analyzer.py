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

import re
import warnings
from collections.abc import AsyncIterator

try:
    import jwt
except ImportError:  # pyjwt ships in the optional [scanners] extra
    jwt = None  # type: ignore[assignment]

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register

SCANNER_NAME = "jwt"

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

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


__all__ = ["JwtScanner", "find_jwts", "analyze_jwt", "DEFAULT_SECRETS"]
