"""Model-agnostic LLM client — spec parsing, redaction, and the three protocols."""

from __future__ import annotations

import asyncio

import httpx
import pytest

from orthrus.ai import providers
from orthrus.ai.providers import (
    LLMClient,
    LLMConfig,
    LLMError,
    parse_spec,
    redact_for_llm,
    resolve_config,
)

# --- spec + config --------------------------------------------------------

def test_parse_spec():
    assert parse_spec("anthropic:claude-sonnet-5") == ("anthropic", "claude-sonnet-5")
    assert parse_spec("ollama") == ("ollama", "llama3.1")  # default model
    assert parse_spec("") == ("anthropic", "claude-sonnet-5")


def test_resolve_config_env_key(monkeypatch):
    monkeypatch.delenv("ORTHRUS_LLM_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k-abc")
    cfg = resolve_config("anthropic:claude-sonnet-5")
    assert cfg.provider == "anthropic" and cfg.model == "claude-sonnet-5" and cfg.api_key == "k-abc"


def test_ollama_is_local():
    assert LLMConfig("ollama", "llama3.1").is_local is True
    assert LLMConfig("anthropic", "x").is_local is False


# --- redaction (never ship secrets to a remote model) ---------------------

def test_redact_for_llm():
    raw = (
        "GET /a HTTP/1.1\r\nAuthorization: Bearer sk-abcdefghijklmnopqrstuvwx\r\n"
        "Cookie: session=deadbeef\r\napi_key=AKIAZZZZZZZZZZZZZZZZ\r\n"
    )
    out = redact_for_llm(raw)
    assert "sk-abcdefghijklmnopqrstuvwx" not in out
    assert "session=deadbeef" not in out
    assert "AKIAZZZZZZZZZZZZZZZZ" not in out
    assert "[REDACTED" in out


# --- the three protocols (fake transport, no network) ---------------------

class _FakeResp:
    def __init__(self, payload, status=200):
        self._p = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPError(f"status {self.status_code}")

    def json(self):
        return self._p


class _Router:
    """Routes POSTs by URL to the right provider response shape; records calls."""

    posts: list = []
    status = 200

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, json=None, headers=None):
        _Router.posts.append({"url": url, "json": json, "headers": headers or {}})
        if _Router.status >= 400:
            return _FakeResp({}, _Router.status)
        if "anthropic.com" in url:
            return _FakeResp({"content": [{"type": "text", "text": "ANTHROPIC-OUT"}]})
        if url.endswith("/chat/completions"):
            return _FakeResp({"choices": [{"message": {"content": "OPENAI-OUT"}}]})
        if url.endswith("/api/chat"):
            return _FakeResp({"message": {"content": "OLLAMA-OUT"}})
        return _FakeResp({})


def _use_router(monkeypatch):
    _Router.posts = []
    _Router.status = 200
    monkeypatch.setattr(providers.httpx, "AsyncClient", _Router)


def test_anthropic_protocol(monkeypatch):
    _use_router(monkeypatch)
    out = asyncio.run(LLMClient(LLMConfig("anthropic", "m", api_key="k")).complete("sys", "usr"))
    assert out == "ANTHROPIC-OUT"
    call = _Router.posts[-1]
    assert call["url"].endswith("/v1/messages") and call["headers"]["x-api-key"] == "k"
    assert call["json"]["system"] == "sys"


def test_openai_protocol(monkeypatch):
    _use_router(monkeypatch)
    out = asyncio.run(LLMClient(LLMConfig("openai", "gpt-4o", api_key="k")).complete("sys", "usr"))
    assert out == "OPENAI-OUT"
    call = _Router.posts[-1]
    assert call["url"] == "https://api.openai.com/v1/chat/completions"
    assert call["headers"]["Authorization"] == "Bearer k"
    assert call["json"]["messages"][0] == {"role": "system", "content": "sys"}


def test_openai_compatible_needs_base_url(monkeypatch):
    _use_router(monkeypatch)
    with pytest.raises(LLMError):
        asyncio.run(LLMClient(LLMConfig("openai-compatible", "m")).complete("s", "u"))
    # with a base URL it works (covers Groq/vLLM/LM Studio/OpenRouter/…)
    cfg = LLMConfig("openai-compatible", "m", base_url="http://localhost:8000/v1")
    assert asyncio.run(LLMClient(cfg).complete("s", "u")) == "OPENAI-OUT"


def test_ollama_protocol_local_no_key(monkeypatch):
    _use_router(monkeypatch)
    out = asyncio.run(LLMClient(LLMConfig("ollama", "llama3.1")).complete("sys", "usr"))
    assert out == "OLLAMA-OUT"
    assert _Router.posts[-1]["url"] == "http://localhost:11434/api/chat"


def test_http_error_wrapped_as_llmerror(monkeypatch):
    _use_router(monkeypatch)
    _Router.status = 500
    with pytest.raises(LLMError):
        asyncio.run(LLMClient(LLMConfig("anthropic", "m", api_key="k")).complete("s", "u"))


def test_remote_request_is_redacted_before_send(monkeypatch):
    _use_router(monkeypatch)
    secret = "Authorization: Bearer sk-abcdefghijklmnopqrstuvwx"
    asyncio.run(LLMClient(LLMConfig("openai", "gpt-4o", api_key="k")).complete("s", f"evidence:\n{secret}"))
    sent = _Router.posts[-1]["json"]["messages"][1]["content"]
    assert "sk-abcdefghijklmnopqrstuvwx" not in sent  # redacted before leaving the host
