"""Cost ledger — turn spend transparency from a promise into a receipt (PRD §10).

An append-only ledger of what an engagement costs: LLM tokens (auto-recorded when
you use the copilot with a model), and anything else you log (OAST, VPS, API
quota). ``orthrus cost`` rolls it up by provider/category and per program.

Token cost is a blended estimate (chars/4 ≈ tokens, times a per-model
USD/1k-token rate) — a guide, not a bill; override rates via ``ORTHRUS_LLM_RATE``.
Stored as JSON Lines at ``$ORTHRUS_HOME/cost.jsonl``.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

# Rough blended USD per 1k tokens. Local models are free; unknowns fall back low.
_RATES = {
    "gpt-4o": 0.005, "gpt-4": 0.03, "gpt-5": 0.01,
    "claude-opus": 0.015, "claude-sonnet": 0.003, "claude-haiku": 0.001,
    "gemini": 0.002, "glm": 0.001, "llama": 0.0, "qwen": 0.0, "mistral": 0.0, "ollama": 0.0,
}


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def default_cost_path() -> Path:
    home = os.environ.get("ORTHRUS_HOME")
    base = Path(home) if home else Path.home() / ".orthrus"
    return base / "cost.jsonl"


def rate_for(model: str) -> float:
    env = os.environ.get("ORTHRUS_LLM_RATE")
    if env:
        try:
            return float(env)
        except ValueError:
            pass
    m = (model or "").lower()
    for key, rate in _RATES.items():
        if key in m:
            return rate
    return 0.001  # conservative default for an unknown hosted model


def estimate_llm_cost(model: str, prompt: str, response: str) -> tuple[int, float]:
    """Return (approx_tokens, approx_usd) for one LLM call."""
    tokens = (len(prompt or "") + len(response or "")) // 4
    return tokens, round(tokens / 1000 * rate_for(model), 6)


class CostLedger:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else default_cost_path()

    def append(self, category: str, provider: str, model: str, quantity: float, unit: str,
               cost_usd: float, *, program: str = "") -> dict:
        entry = {"ts": _now(), "category": category, "provider": provider, "model": model,
                 "quantity": quantity, "unit": unit, "cost_usd": round(cost_usd, 6),
                 "program": program}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def record_llm(self, model: str, prompt: str, response: str, *, provider: str = "",
                   program: str = "") -> dict:
        tokens, usd = estimate_llm_cost(model, prompt, response)
        return self.append("llm", provider or model.split(":", 1)[0], model, tokens, "tokens", usd,
                           program=program)

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out

    def summary(self, program: str | None = None) -> dict:
        rows = self.entries()
        if program:
            rows = [r for r in rows if r.get("program", "").lower() == program.lower()]
        by_provider: dict[str, float] = {}
        by_category: dict[str, float] = {}
        total = 0.0
        for r in rows:
            c = float(r.get("cost_usd", 0) or 0)
            total += c
            by_provider[r.get("provider", "?")] = round(by_provider.get(r.get("provider", "?"), 0.0) + c, 6)
            by_category[r.get("category", "?")] = round(by_category.get(r.get("category", "?"), 0.0) + c, 6)
        return {"entries": len(rows), "total_usd": round(total, 4),
                "by_provider": by_provider, "by_category": by_category}


__all__ = ["CostLedger", "estimate_llm_cost", "rate_for", "default_cost_path"]
