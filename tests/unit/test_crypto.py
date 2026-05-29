"""Tests for AES-256-GCM at-rest encryption helpers."""

from __future__ import annotations

from orthrus.utils.crypto import decrypt, encrypt, generate_key, is_encrypted, protect


def test_roundtrip():
    key = generate_key()
    secret = "AKIAEXAMPLE / password123 / root:x:0:0"
    token = encrypt(secret, key)
    assert is_encrypted(token)
    assert token != secret
    assert decrypt(token, key) == secret


def test_protect_without_key_is_passthrough():
    assert protect("sensitive", None) == "sensitive"
    assert is_encrypted(protect("sensitive", None) or "") is False


def test_protect_with_key_encrypts():
    key = generate_key()
    token = protect("sensitive", key)
    assert is_encrypted(token)
    assert decrypt(token, key) == "sensitive"


def test_decrypt_plaintext_passthrough():
    # Non-encrypted values pass through decrypt unchanged.
    assert decrypt("plain text", generate_key()) == "plain text"


def test_distinct_nonces():
    key = generate_key()
    assert encrypt("x", key) != encrypt("x", key)  # random nonce each time
