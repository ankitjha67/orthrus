"""Autonomous agent orchestrator (`orthrus agent`) — planner + bounded runner.

The safety-critical property under test: the agent can only ever act through the
allow-list of registered scanners. A hallucinated/off-list tool is dropped by the
parser and again by the runner before anything executes; there is no path to a
shell or arbitrary code.
"""

from __future__ import annotations

import asyncio

from click.testing import CliRunner

from orthrus import main
from orthrus.agent import planner as P
from orthrus.agent.planner import (
    AgentAction,
    AgentState,
    ToolSpec,
    build_catalog,
    build_planner_prompt,
    deterministic_plan,
    parse_plan_response,
    plan_actions,
    validate_action,
)
from orthrus.agent.runner import AgentRunner
from orthrus.scanners.registry import available_modules

# A small fake catalog for logic tests (decoupled from the real registry).
_CAT = {
    "a": ToolSpec("a", min_aggressiveness="passive", description="passive check"),
    "b": ToolSpec("b", min_aggressiveness="aggressive", description="aggressive check"),
    "c": ToolSpec("c", min_aggressiveness="normal", description="normal check"),
}


# --- catalog / allow-list ------------------------------------------------

def test_catalog_is_the_scanner_registry():
    cat = build_catalog()
    assert set(cat) == set(available_modules()) and len(cat) > 20
    assert all(spec.kind == "scanner" for spec in cat.values())


def test_validate_action_allow_list():
    assert validate_action(AgentAction(tool="a"), _CAT) is True
    assert validate_action(AgentAction(tool="run_shell"), _CAT) is False
    assert validate_action(AgentAction(tool="../../etc/passwd"), _CAT) is False


# --- plan parsing --------------------------------------------------------

def test_parse_drops_off_allow_list_tools():
    text = '{"actions": [{"tool": "a", "rationale": "x"}, {"tool": "run_shell", "rationale": "pwn"}]}'
    actions = parse_plan_response(text, _CAT)
    assert [a.tool for a in actions] == ["a"]  # run_shell dropped


def test_parse_done_and_fenced_and_array():
    assert parse_plan_response('{"done": true, "actions": []}', _CAT) == []
    fenced = parse_plan_response('```json\n{"actions":[{"tool":"c"}]}\n```', _CAT)
    assert [a.tool for a in fenced] == ["c"]
    arr = parse_plan_response('[{"tool":"a"},{"tool":"nope"}]', _CAT)
    assert [a.tool for a in arr] == ["a"]


def test_parse_garbage_is_none():
    assert parse_plan_response("i cannot help with that", _CAT) is None
    assert parse_plan_response("", _CAT) is None


# --- deterministic policy ------------------------------------------------

def test_deterministic_respects_aggressiveness_and_executed():
    passive = deterministic_plan(AgentState("http://t", aggressiveness="passive"), _CAT)
    assert [a.tool for a in passive] == ["a"]  # only the passive tool
    aggressive = deterministic_plan(AgentState("http://t", aggressiveness="aggressive"), _CAT)
    assert {a.tool for a in aggressive} == {"a", "b", "c"}
    partial = deterministic_plan(
        AgentState("http://t", aggressiveness="aggressive", executed=["a", "b"]), _CAT)
    assert [a.tool for a in partial] == ["c"]  # already-run excluded


def test_prompt_lists_tools_and_target():
    prompt = build_planner_prompt(AgentState("http://shop.local"), _CAT)
    assert "http://shop.local" in prompt and "allow-list" in prompt.lower()
    assert "a:" in prompt and "b:" in prompt


# --- plan_actions (LLM path with a fake transport) -----------------------

def test_plan_actions_no_key_uses_deterministic():
    res = asyncio.run(plan_actions(AgentState("http://t", aggressiveness="passive"), _CAT, None))
    assert [a.tool for a in res] == ["a"]


def test_plan_actions_llm_parsed(monkeypatch):
    async def fake_llm(prompt, key, model):
        return '{"actions":[{"tool":"c","rationale":"try normal"}]}'

    monkeypatch.setattr(P, "_call_llm", fake_llm)
    res = asyncio.run(plan_actions(AgentState("http://t"), _CAT, "key"))
    assert [a.tool for a in res] == ["c"]


def test_plan_actions_llm_failure_falls_back(monkeypatch):
    async def dead_llm(prompt, key, model):
        return None

    monkeypatch.setattr(P, "_call_llm", dead_llm)
    res = asyncio.run(plan_actions(AgentState("http://t", aggressiveness="normal"), _CAT, "key"))
    assert {a.tool for a in res} == {"a", "c"}  # deterministic normal-rank fallback


# --- runner --------------------------------------------------------------

def test_runner_dry_run_executes_nothing():
    calls: list = []

    async def planr(state):
        return [AgentAction("a"), AgentAction("c")]

    async def execute(modules, state):
        calls.append(modules)
        return []

    runner = AgentRunner("http://t", _CAT, planner=planr, execute_fn=execute)
    report = asyncio.run(runner.run(dry_run=True))
    assert report.dry_run and [a.tool for a in report.plan] == ["a", "c"]
    assert report.steps == [] and calls == []  # nothing executed


def test_runner_live_loop_and_allow_list_gate():
    executed: list = []
    plans = [
        [AgentAction("a"), AgentAction("run_shell"), AgentAction("c")],  # off-list dropped
        [],  # done
    ]

    async def planr(state):
        return plans.pop(0) if plans else []

    async def execute(modules, state):
        executed.append(list(modules))
        return [{"vuln_type": "x", "severity": "high", "url": "http://t/1"}]

    runner = AgentRunner("http://t", _CAT, planner=planr, execute_fn=execute, max_steps=3)
    report = asyncio.run(runner.run(dry_run=False))
    # run_shell never reached the executor; only allow-listed a, c did.
    assert executed == [["a", "c"]]
    assert "run_shell" not in [m for step in executed for m in step]
    assert len(report.findings) == 1 and "done" in report.stopped_reason


def test_runner_respects_max_steps():
    pool = ["a", "b", "c"]

    async def planr(state):
        remaining = [t for t in pool if t not in state.executed]
        return [AgentAction(remaining[0])] if remaining else []

    async def execute(modules, state):
        return []

    # 3 tools available but max_steps=2 → stops at the cap with 'c' still unrun.
    runner = AgentRunner("http://t", _CAT, planner=planr, execute_fn=execute, max_steps=2)
    report = asyncio.run(runner.run(dry_run=False))
    assert len(report.steps) == 2 and "max-steps" in report.stopped_reason


def test_runner_live_requires_executor():
    async def planr(state):
        return [AgentAction("a")]

    runner = AgentRunner("http://t", _CAT, planner=planr, execute_fn=None)
    try:
        asyncio.run(runner.run(dry_run=False))
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


# --- CLI (dry-run, deterministic — no network) ---------------------------

def test_cli_agent_dry_run_shows_plan():
    r = CliRunner().invoke(main.cli, [
        "--no-banner", "agent", "-t", "http://t", "--scope", "t", "--no-llm", "--dry-run",
        "--aggressiveness", "passive",
    ])
    assert r.exit_code == 0, r.output
    assert "Plan:" in r.output


def test_cli_agent_dry_run_json():
    r = CliRunner().invoke(main.cli, [
        "--no-banner", "agent", "-t", "http://t", "--scope", "t", "--no-llm", "--dry-run", "--json",
    ])
    assert r.exit_code == 0, r.output
    assert '"dry_run": true' in r.output
