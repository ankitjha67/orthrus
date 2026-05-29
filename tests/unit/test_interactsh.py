"""Interactsh OOB collaborator client: crypto round-trip + token shape.

The decisive check is that our poll path exactly inverts the ProjectDiscovery
server's encryption: a per-poll AES key wrapped with our RSA public key
(RSA-OAEP, SHA-256), and each interaction as AES-CFB ciphertext prefixed by its
IV. We synthesise a standards-compliant server response and confirm the client
decrypts and buckets it — no network required.
"""

from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from orthrus.core.callback import _XID_ALPHABET, InteractshCallbackClient, _rand_id


def _server_response(public_key, interactions: list[dict], *, key_size: int = 32) -> dict:
    """Mimic an Interactsh server's /poll body for the given interactions."""
    aes_key = os.urandom(key_size)  # real servers use AES-256 (32 bytes)
    wrapped = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    data = []
    for obj in interactions:
        iv = os.urandom(16)
        enc = Cipher(algorithms.AES(aes_key), modes.CFB(iv)).encryptor()
        ct = iv + enc.update(json.dumps(obj).encode()) + enc.finalize()
        data.append(base64.b64encode(ct).decode())
    return {"data": data, "aes_key": base64.b64encode(wrapped).decode()}


class _FakePollResp:
    def __init__(self, body: dict) -> None:
        self.status_code = 200
        self._body = body

    def json(self) -> dict:
        return self._body


class _FakePollClient:
    def __init__(self, body: dict) -> None:
        self._body = body
        self.polls = 0

    async def get(self, url: str, params=None, headers=None) -> _FakePollResp:
        self.polls += 1
        return _FakePollResp(self._body)


def _registered_client() -> InteractshCallbackClient:
    client = InteractshCallbackClient(server="oast.test")
    client._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client._domain = "oast.test"
    client._registered = True
    return client


# --------------------------------------------------------------------- tokens
def test_rand_id_uses_xid_alphabet() -> None:
    rid = _rand_id(20)
    assert len(rid) == 20
    assert set(rid) <= set(_XID_ALPHABET)


def test_new_token_is_unique_subdomain() -> None:
    client = _registered_client()
    host, url = client.new_token()
    assert len(host) == 33  # 20-char correlation id + 13-char random suffix
    assert host.startswith(client._correlation_id)
    assert url == f"https://{host}.oast.test"
    host2, _ = client.new_token()
    assert host2 != host  # fresh suffix each time


# ----------------------------------------------------------------- decryption
async def test_poll_decrypts_and_buckets_interactions() -> None:
    client = _registered_client()
    host, _ = client.new_token()
    interactions = [
        {
            "protocol": "dns",
            "unique-id": host,
            "full-id": host,
            "remote-address": "203.0.113.9",
            "q-type": "A",
            "raw-request": ";; QUESTION SECTION",
        },
        {
            "protocol": "http",
            "unique-id": host,
            "full-id": host,
            "remote-address": "203.0.113.9",
            "raw-request": "GET / HTTP/1.1",
        },
    ]
    client._client = _FakePollClient(_server_response(client._private_key.public_key(), interactions))

    hits = await client.poll(host)
    assert len(hits) == 2
    assert hits[0].protocol == "dns"
    assert hits[0].source_ip == "203.0.113.9"
    assert hits[0].token == host
    assert "GET /" in hits[1].body


async def test_poll_decrypts_aes128_key() -> None:
    # The client must handle whatever AES key length the server chose.
    client = _registered_client()
    host, _ = client.new_token()
    interactions = [{"protocol": "dns", "unique-id": host, "remote-address": "198.51.100.7"}]
    body = _server_response(client._private_key.public_key(), interactions, key_size=16)
    client._client = _FakePollClient(body)
    hits = await client.poll(host)
    assert hits and hits[0].source_ip == "198.51.100.7"


async def test_poll_returns_empty_for_unmatched_token() -> None:
    client = _registered_client()
    host, _ = client.new_token()
    interactions = [{"protocol": "dns", "unique-id": host, "remote-address": "203.0.113.9"}]
    client._client = _FakePollClient(_server_response(client._private_key.public_key(), interactions))
    other_host, _ = client.new_token()
    assert await client.poll(other_host) == []


async def test_poll_handles_empty_server_response() -> None:
    client = _registered_client()
    host, _ = client.new_token()
    client._client = _FakePollClient({"data": [], "aes_key": None})
    assert await client.poll(host) == []
