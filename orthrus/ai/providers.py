"""Model-agnostic LLM client - local or any market model, over plain httpx.

One tiny client speaks three wire protocols, which between them cover essentially
every model a user might have:

* **anthropic**          - Claude (``api.anthropic.com``)
* **openai**             - OpenAI, and via ``ORTHRUS_LLM_BASE_URL`` any
  OpenAI-*compatible* endpoint: Azure OpenAI, Groq, Together, OpenRouter,
  Mistral, DeepSeek, vLLM, LM Studio, LocalAI, …
* **ollama**             - a **local** Ollama server (default ``localhost:11434``)

Selection is a ``provider:model`` spec (``anthropic:claude-sonnet-5``,
``ollama:llama3.1``, ``openai:gpt-4o``); keys/base-url come from env. No SDKs -
just httpx (already a core dependency). Anything sent to a **remote** model is
run through :func:`redact_for_llm` first, so credentials/cookies in captured
evidence never leave the host (the full evidence still lives in the deterministic
report).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

import httpx

from orthrus.utils.logger import get_logger

logger = get_logger("ai.providers")

_DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-5",
    "openai": "gpt-4o",
    "openai-compatible": "",
    "ollama": "llama3.1",
}
_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
_OPENAI_DEFAULT_BASE = "https://api.openai.com/v1"
_OLLAMA_DEFAULT_BASE = "http://localhost:11434"

# Redaction applied to anything sent to a *remote* model. The narrative never
# needs the literal secret; the deterministic report keeps the full evidence.
_REDACTIONS = [
    (re.compile(r"(?im)^(authorization|proxy-authorization)\s*:\s*.+$"), r"\1: [REDACTED]"),
    (re.compile(r"(?im)^(cookie|set-cookie)\s*:\s*.+$"), r"\1: [REDACTED]"),
    (re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[=:]\s*[^\s&\"']+"), r"\1=[REDACTED]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED-AWS-KEY]"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "[REDACTED-KEY]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}"), "[REDACTED-JWT]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     "[REDACTED-PRIVATE-KEY]"),
]


def redact_for_llm(text: str) -> str:
    """Mask credentials/cookies/keys in text bound for a remote model."""
    if not text:
        return text
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


class LLMError(Exception):
    """Any failure talking to the model (network, auth, bad response)."""


def parse_spec(spec: str) -> tuple[str, str]:
    """``'anthropic:claude-sonnet-5'`` → ``('anthropic', 'claude-sonnet-5')``.

    A bare ``'ollama'`` resolves the provider's default model.
    """
    spec = (spec or "").strip()
    provider, sep, model = spec.partition(":")
    provider = provider.lower().strip() or "anthropic"
    model = (model.strip() if sep else "") or _DEFAULT_MODELS.get(provider, "")
    return provider, model


@dataclass
class LLMConfig:
    provider: str
    model: str
    api_key: str | None = None
    base_url: str | None = None
    temperature: float = 0.3
    max_tokens: int = 4096
    timeout: float = 180.0

    @property
    def is_local(self) -> bool:
        base = self.base_url or (_OLLAMA_DEFAULT_BASE if self.provider == "ollama" else "")
        return self.provider == "ollama" or "localhost" in base or "127.0.0.1" in base


def _env_timeout(default: float = 180.0) -> float:
    """Per-request timeout, overridable via ``ORTHRUS_LLM_TIMEOUT`` (seconds).

    Slow reasoning models and cold-started hosted endpoints can take minutes to
    first token; the default suits fast models but is raisable for the rest.
    """
    raw = os.environ.get("ORTHRUS_LLM_TIMEOUT")
    if not raw:
        return default
    try:
        val = float(raw)
    except ValueError:
        logger.warning("ignoring invalid ORTHRUS_LLM_TIMEOUT=%r; using %.0fs", raw, default)
        return default
    return val if val > 0 else default


def resolve_config(spec: str, *, model: str | None = None, temperature: float = 0.3,
                   max_tokens: int = 4096) -> LLMConfig:
    """Resolve a ``provider:model`` spec + env (keys, base URL) into an LLMConfig."""
    provider, spec_model = parse_spec(spec)
    resolved_model = model or spec_model or _DEFAULT_MODELS.get(provider, "")
    api_key = os.environ.get("ORTHRUS_LLM_API_KEY")
    if not api_key:
        if provider == "anthropic":
            api_key = os.environ.get("ORTHRUS_ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        elif provider in ("openai", "openai-compatible"):
            api_key = os.environ.get("OPENAI_API_KEY")
    return LLMConfig(
        provider=provider, model=resolved_model, api_key=api_key,
        base_url=os.environ.get("ORTHRUS_LLM_BASE_URL"),
        temperature=temperature, max_tokens=max_tokens, timeout=_env_timeout(),
    )


class LLMClient:
    """A thin async chat client over the three protocols."""

    def __init__(self, config: LLMConfig) -> None:
        self.config = config

    async def complete(self, system: str, user: str, *, max_tokens: int | None = None,
                       temperature: float | None = None) -> str:
        cfg = self.config
        mt = max_tokens or cfg.max_tokens
        temp = cfg.temperature if temperature is None else temperature
        if not cfg.is_local:  # never ship raw credentials/cookies to a remote model
            user = redact_for_llm(user)
        try:
            if cfg.provider == "anthropic":
                return await self._anthropic(system, user, mt, temp)
            if cfg.provider in ("openai", "openai-compatible"):
                return await self._openai(system, user, mt, temp)
            if cfg.provider == "ollama":
                return await self._ollama(system, user, mt, temp)
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            raise LLMError(f"{cfg.provider} request failed: {exc}") from exc
        raise LLMError(f"unknown LLM provider '{cfg.provider}'")

    async def _post(self, url: str, payload: dict, headers: dict) -> dict:
        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            return resp.json()

    async def _anthropic(self, system: str, user: str, mt: int, temp: float) -> str:
        if not self.config.api_key:
            raise LLMError("anthropic needs an API key (ANTHROPIC_API_KEY / ORTHRUS_LLM_API_KEY)")
        data = await self._post(
            _ANTHROPIC_URL,
            {"model": self.config.model, "max_tokens": mt, "temperature": temp,
             "system": system, "messages": [{"role": "user", "content": user}]},
            {"x-api-key": self.config.api_key, "anthropic-version": "2023-06-01",
             "content-type": "application/json"},
        )
        return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")

    async def _openai(self, system: str, user: str, mt: int, temp: float) -> str:
        base = self.config.base_url or (
            _OPENAI_DEFAULT_BASE if self.config.provider == "openai" else None)
        if not base:
            raise LLMError("openai-compatible needs ORTHRUS_LLM_BASE_URL")
        headers = {"content-type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        data = await self._post(
            base.rstrip("/") + "/chat/completions",
            {"model": self.config.model, "max_tokens": mt, "temperature": temp,
             "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]},
            headers,
        )
        return data["choices"][0]["message"]["content"] or ""

    async def _ollama(self, system: str, user: str, mt: int, temp: float) -> str:
        base = self.config.base_url or _OLLAMA_DEFAULT_BASE
        data = await self._post(
            base.rstrip("/") + "/api/chat",
            {"model": self.config.model, "stream": False,
             "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
             "options": {"temperature": temp, "num_predict": mt}},
            {"content-type": "application/json"},
        )
        return data.get("message", {}).get("content", "") or ""


__all__ = ["LLMClient", "LLMConfig", "LLMError", "parse_spec", "resolve_config", "redact_for_llm"]
