"""AES-256-GCM encryption for sensitive data at rest (PRD §12.2).

Extracted secrets (credentials, tokens, file contents) are encrypted before
persistence when an encryption key is configured (HYDRA_ENCRYPTION_KEY, a
base64 32-byte key from :func:`generate_key`). Without a key, data is stored
as-is. Requires the cryptography package (the [scanners] extra).
"""

from __future__ import annotations

import base64
import os

_PREFIX = "enc:gcm:"

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None  # type: ignore[assignment]


def generate_key() -> str:
    """Return a fresh base64-encoded 256-bit key."""
    if AESGCM is None:
        raise RuntimeError("cryptography not installed ([scanners] extra)")
    return base64.b64encode(AESGCM.generate_key(bit_length=256)).decode("ascii")


def encrypt(plaintext: str, key_b64: str) -> str:
    if AESGCM is None:
        return plaintext
    key = base64.b64decode(key_b64)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return _PREFIX + base64.b64encode(nonce + ct).decode("ascii")


def decrypt(token: str, key_b64: str) -> str:
    if not token.startswith(_PREFIX) or AESGCM is None:
        return token
    key = base64.b64decode(key_b64)
    raw = base64.b64decode(token[len(_PREFIX):])
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")


def protect(value: str | None, key_b64: str | None) -> str | None:
    """Encrypt ``value`` if a key is configured; otherwise return it unchanged."""
    if value is None or not key_b64:
        return value
    return encrypt(value, key_b64)


def is_encrypted(value: str | None) -> bool:
    return bool(value) and value.startswith(_PREFIX)


__all__ = ["generate_key", "encrypt", "decrypt", "protect", "is_encrypted"]
