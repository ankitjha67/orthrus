"""AI augmentation layer - grounded, provider-agnostic LLM features.

The deterministic scanners produce the ground truth; this layer reasons and
writes *over* that truth. The flagship is the Big-Four-grade consultant report
(`orthrus ai-report`), backed by a model-agnostic client that speaks to local
(Ollama) or any market model (Claude / OpenAI / any OpenAI-compatible endpoint).
"""

from __future__ import annotations

from orthrus.ai.providers import (
    LLMClient,
    LLMConfig,
    LLMError,
    parse_spec,
    redact_for_llm,
    resolve_config,
)
from orthrus.ai.render import markdown_to_html
from orthrus.ai.report_writer import write_consultant_report

__all__ = [
    "LLMClient",
    "LLMConfig",
    "LLMError",
    "parse_spec",
    "resolve_config",
    "redact_for_llm",
    "markdown_to_html",
    "write_consultant_report",
]
