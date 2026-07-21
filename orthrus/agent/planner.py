"""Bounded planner for the autonomous orchestrator.

The agent's "brain": given the target and what's been found so far, decide which
of ORTHRUS's **existing, scope-enforced, non-destructive** tools to run next. The
action space is a hard allow-list built from the scanner registry - the planner
can only ever select a registered module, never a shell command or arbitrary
code. An LLM proposes the plan; a deterministic policy is the fallback when no
API key is present (and what the tests drive). Every proposed action is
re-validated against the allow-list before it can execute, so a hallucinated or
malformed tool name is simply dropped.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from orthrus.triage import ANTHROPIC_URL, DEFAULT_MODEL

_AGGR_RANK = {"passive": 0, "normal": 1, "aggressive": 2}
_MAX_PLAN = 16


@dataclass(frozen=True)
class ToolSpec:
    name: str
    kind: str = "scanner"
    description: str = ""
    vuln_type: str = ""
    min_aggressiveness: str = "normal"


@dataclass
class AgentAction:
    tool: str
    rationale: str = ""
    args: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"tool": self.tool, "rationale": self.rationale, "args": self.args}


@dataclass
class AgentState:
    target: str
    aggressiveness: str = "normal"
    max_steps: int = 3
    step: int = 0
    executed: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)

    def findings_brief(self, limit: int = 20) -> str:
        if not self.findings:
            return "none yet"
        return "; ".join(
            f"{f.get('severity', '?')} {f.get('vuln_type', '?')} @ {f.get('url', '')}"
            for f in self.findings[:limit]
        )


def build_catalog() -> dict[str, ToolSpec]:
    """The allow-list: every registered scanner module the agent may run."""
    import orthrus.scanners  # noqa: F401  (import populates the registry)
    from orthrus.scanners.registry import SCANNER_REGISTRY

    catalog: dict[str, ToolSpec] = {}
    for cls in SCANNER_REGISTRY.values():
        doc = (cls.__doc__ or "").strip().splitlines()
        catalog[cls.name] = ToolSpec(
            name=cls.name,
            kind="scanner",
            description=doc[0].strip() if doc else "",
            vuln_type=getattr(cls, "vuln_type", ""),
            min_aggressiveness=getattr(getattr(cls, "min_aggressiveness", None), "value", "normal"),
        )
    return catalog


def validate_action(action: AgentAction, catalog: dict[str, ToolSpec]) -> bool:
    """The safety gate: an action may execute only if its tool is on the allow-list."""
    return action.tool in catalog


def _eligible(state: AgentState, catalog: dict[str, ToolSpec]) -> list[str]:
    rank = _AGGR_RANK.get(state.aggressiveness, 1)
    done = set(state.executed)
    return [
        name for name, spec in sorted(catalog.items())
        if name not in done and _AGGR_RANK.get(spec.min_aggressiveness, 1) <= rank
    ]


def deterministic_plan(state: AgentState, catalog: dict[str, ToolSpec]) -> list[AgentAction]:
    """No-LLM fallback: run every not-yet-run scanner allowed at this aggressiveness."""
    eligible = _eligible(state, catalog)[:_MAX_PLAN]
    return [AgentAction(tool=n, rationale="baseline coverage (deterministic policy)") for n in eligible]


def build_planner_prompt(state: AgentState, catalog: dict[str, ToolSpec]) -> str:
    tools = "\n".join(
        f"- {s.name}: {s.description or s.vuln_type} (min aggressiveness: {s.min_aggressiveness})"
        for s in sorted(catalog.values(), key=lambda s: s.name)
    )
    return (
        "You are an autonomous but bounded web-app pentest orchestrator running against an "
        "AUTHORIZED target. You may ONLY select tools from the allow-list below by exact name - "
        "every tool is scope-enforced and non-destructive; you cannot run shells or arbitrary "
        "code. Choose the next batch of scanners to run based on the target and findings so far, "
        "avoiding ones already run. Respond with JSON only:\n"
        '{"actions": [{"tool": "<name>", "rationale": "<why>"}], "done": false}\n'
        'Set "done": true with an empty actions list when coverage is sufficient.\n\n'
        f"Target: {state.target}\n"
        f"Aggressiveness: {state.aggressiveness}\n"
        f"Already run: {', '.join(state.executed) or 'none'}\n"
        f"Findings so far: {state.findings_brief()}\n\n"
        f"Allow-listed tools:\n{tools}"
    )


def parse_plan_response(text: str, catalog: dict[str, ToolSpec]) -> list[AgentAction] | None:
    """Parse an LLM plan into allow-listed actions. None on parse failure; [] on explicit done."""
    blob = _extract_json(text)
    if blob is None:
        return None
    try:
        data = json.loads(blob)
    except (ValueError, TypeError):
        return None
    if isinstance(data, dict):
        if data.get("done") and not data.get("actions"):
            return []
        items = data.get("actions", [])
    elif isinstance(data, list):
        items = data
    else:
        return None
    actions: list[AgentAction] = []
    for it in items:
        if isinstance(it, dict) and isinstance(it.get("tool"), str):
            action = AgentAction(tool=it["tool"], rationale=str(it.get("rationale", "")))
            if validate_action(action, catalog):  # drop anything off the allow-list
                actions.append(action)
    return actions[:_MAX_PLAN]


def _extract_json(text: str) -> str | None:
    if not text:
        return None
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        return fence.group(1).strip()
    # Choose whichever bracket type opens first, matched to its last closer, so a
    # bare array isn't mis-sliced by an inner object's braces.
    candidates: list[tuple[int, str]] = []
    for opener, closer in (("{", "}"), ("[", "]")):
        start, end = text.find(opener), text.rfind(closer)
        if 0 <= start < end:
            candidates.append((start, text[start : end + 1]))
    if not candidates:
        return None
    candidates.sort()
    return candidates[0][1]


async def plan_actions(
    state: AgentState, catalog: dict[str, ToolSpec], api_key: str | None, *, model: str = DEFAULT_MODEL
) -> list[AgentAction]:
    """LLM plan (allow-list-filtered), falling back to the deterministic policy."""
    if not api_key:
        return deterministic_plan(state, catalog)
    text = await _call_llm(build_planner_prompt(state, catalog), api_key, model)
    if text is None:
        return deterministic_plan(state, catalog)
    parsed = parse_plan_response(text, catalog)
    return parsed if parsed is not None else deterministic_plan(state, catalog)


async def _call_llm(prompt: str, api_key: str, model: str) -> str | None:
    import httpx

    payload = {"model": model, "max_tokens": 800, "messages": [{"role": "user", "content": prompt}]}
    headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(ANTHROPIC_URL, json=payload, headers=headers)
        if resp.status_code != 200:
            return None
        blocks = resp.json().get("content", [])
        return "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
    except Exception:
        return None


__all__ = [
    "ToolSpec", "AgentAction", "AgentState",
    "build_catalog", "validate_action", "deterministic_plan",
    "build_planner_prompt", "parse_plan_response", "plan_actions",
]
