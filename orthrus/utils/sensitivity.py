"""Sensitive-data detector: turn an accessible response body into evidence.

When an authorization test shows identity B could read identity A's object, the
finding is only as good as its *proof*. This module scans a response body for
high-precision markers of private data - emails, payment-card numbers (Luhn-
checked), IBANs, JWTs/bearer tokens, government IDs, and money/balance fields -
and returns **redacted** samples. Redaction is deliberate: it proves the class of
data exposed without copying a real user's full PII into a report artifact.

A body that carries any *high-value* marker is what separates a genuine
sensitive-data-exposure / BOLA CRITICAL from a match on a public template page.
Patterns are conservative (precision over recall) so the escalation signal stays
trustworthy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# High-value markers escalate severity; low-value ones are contextual only.
_HIGH_VALUE = frozenset({"email", "payment-card", "iban", "jwt", "secret", "gov-id", "money"})

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_JWT = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
# JSON/kv secret fields: "token": "abc...", api_key=..., password: ...
_SECRET_KV = re.compile(
    r"(?i)\b(api[_\-]?key|secret|access[_\-]?token|refresh[_\-]?token|auth[_\-]?token|"
    r"password|passwd|client[_\-]?secret)\b['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9._\-]{8,})"
)
# Money/balance: currency symbol or ISO code next to a number, or a money-ish key
# with a number. Covers the fiat/crypto shown on wallet/deposit/withdraw responses.
_CCY = r"USD|EUR|GBP|INR|RUB|BRL|NGN|TRY|AUD|CAD|UAH|KZT|PLN|BTC|ETH|USDT"
_MONEY = re.compile(
    r"(?i)"
    r"(?:[₹$€£]\s?\d[\d,]*(?:\.\d{1,2})?)"                                  # $4,200.00
    rf"|(?:\b(?:{_CCY})\b\s?\d[\d,]*(?:\.\d{{1,2}})?)"                      # USD 4200.00
    rf"|(?:\d[\d,]*(?:\.\d{{1,2}})?\s?\b(?:{_CCY})\b)"                      # 4200 USD
    r"|(?:\b(?:balance|amount|deposit|withdraw(?:al)?|wallet|credit|payout|bonus)\b"
    rf"['\"]?\s*[:=]\s*['\"]?(?:(?:{_CCY})\s?)?\d[\d,]*(?:\.\d{{1,2}})?)"   # "balance":"USD 4200"
)
_PHONE = re.compile(r"(?<!\d)\+\d[\d\s\-]{7,}\d(?!\d)")
_CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)")


@dataclass(frozen=True)
class SensitiveHit:
    """One class of sensitive data found in a body, with a redacted sample."""

    kind: str
    sample: str

    @property
    def high_value(self) -> bool:
        return self.kind in _HIGH_VALUE


def _luhn_ok(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = ord(ch) - 48
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _redact_email(value: str) -> str:
    local, _, domain = value.partition("@")
    head = local[0] if local else "*"
    dom_tld = domain.rsplit(".", 1)[-1] if "." in domain else "?"
    return f"{head}***@***.{dom_tld}"


def _redact_tail(value: str, keep: int = 4) -> str:
    digits = re.sub(r"\D", "", value)
    return "****" + digits[-keep:] if len(digits) >= keep else "****"


def _redact_token(value: str) -> str:
    return value[:6] + "…" if len(value) > 6 else "…"


def scan_sensitive(text: str, *, max_hits: int = 6) -> list[SensitiveHit]:
    """Return de-duplicated, redacted sensitive-data hits found in ``text``.

    Ordered high-value first so callers can show the strongest evidence. Empty
    for a body with no private-data markers (e.g. a public template page).
    """
    if not text:
        return []
    body = text[:200_000]  # cap work on huge bodies
    hits: list[SensitiveHit] = []
    seen: set[str] = set()

    def add(kind: str, sample: str) -> None:
        key = f"{kind}:{sample}"
        if key not in seen:
            seen.add(key)
            hits.append(SensitiveHit(kind, sample))

    for m in _EMAIL.finditer(body):
        add("email", _redact_email(m.group(0)))
    for _ in _JWT.finditer(body):
        add("jwt", "eyJ… (JWT)")
    for m in _SECRET_KV.finditer(body):
        add("secret", f"{m.group(1).lower()}={_redact_token(m.group(2))}")
    for m in _IBAN.finditer(body):
        add("iban", _redact_tail(m.group(0)))
    for _ in _SSN.finditer(body):
        add("gov-id", "***-**-****")
    for m in _MONEY.finditer(body):
        add("money", m.group(0).strip()[:24])
    for m in _CARD_CANDIDATE.finditer(body):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            add("payment-card", "**** **** **** " + digits[-4:])
    for m in _PHONE.finditer(body):
        add("phone", _redact_tail(m.group(0), keep=3))

    hits.sort(key=lambda h: (not h.high_value, h.kind))
    return hits[:max_hits]


def has_high_value(hits: list[SensitiveHit]) -> bool:
    """True if any hit is a high-value class (email/card/iban/jwt/secret/gov-id/money)."""
    return any(h.high_value for h in hits)


def describe(hits: list[SensitiveHit]) -> str:
    """A compact evidence string: ``email=a***@***.com, money=$4,200``."""
    return ", ".join(f"{h.kind}={h.sample}" for h in hits)


__all__ = ["SensitiveHit", "scan_sensitive", "has_high_value", "describe"]
