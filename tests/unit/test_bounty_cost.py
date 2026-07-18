"""Cost ledger + LLM cost estimation."""

from __future__ import annotations

from orthrus.bounty.cost import CostLedger, estimate_llm_cost, rate_for


def test_rate_lookup_and_default():
    assert rate_for("claude-sonnet-5") == 0.003
    assert rate_for("gpt-4o") == 0.005
    assert rate_for("ollama:llama3.1") == 0.0
    assert rate_for("z-ai/glm-5.2") == 0.001      # 'glm' rate
    assert rate_for("totally-unknown") == 0.001    # conservative default


def test_env_rate_override(monkeypatch):
    monkeypatch.setenv("ORTHRUS_LLM_RATE", "0.02")
    assert rate_for("anything") == 0.02


def test_estimate_tokens_and_cost():
    tokens, usd = estimate_llm_cost("gpt-4o", "a" * 4000, "b" * 4000)  # 8000 chars ≈ 2000 tokens
    assert tokens == 2000
    assert usd == round(2000 / 1000 * 0.005, 6)   # 0.01


def test_ledger_records_and_summarizes(tmp_path):
    led = CostLedger(tmp_path / "cost.jsonl")
    led.record_llm("gpt-4o", "x" * 4000, "y" * 4000, provider="openai", program="acme")
    led.append("oast", "interactsh", "-", 1, "domain", 1.0, program="acme")
    led.record_llm("ollama:llama3.1", "z" * 4000, "w" * 4000, program="beta")  # free

    s = led.summary()
    assert s["entries"] == 3
    assert s["by_category"]["oast"] == 1.0
    assert s["by_provider"]["openai"] > 0
    assert s["total_usd"] == round(s["by_provider"]["openai"] + 1.0, 4)  # llama is free

    acme = led.summary("acme")
    assert acme["entries"] == 2
    assert led.summary("nobody")["entries"] == 0
