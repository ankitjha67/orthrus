"""Bounded execution loop for the autonomous orchestrator.

Drives the planner in a loop: plan → (validate against the allow-list) → execute
via an injected executor → observe findings → re-plan, up to ``max_steps``. The
executor is a dependency (the CLI wires it to the real scope-enforced
Orchestrator; tests inject a fake), and it is only ever handed allow-listed
module names — the runner filters every planned action through
``validate_action`` before anything runs. ``--dry-run`` produces the plan and
executes nothing.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from orthrus.agent.planner import (
    AgentAction,
    AgentState,
    ToolSpec,
    plan_actions,
    validate_action,
)

# executor(modules, state) -> list of finding dicts produced this step
ExecuteFn = Callable[[list[str], AgentState], Awaitable[list[dict]]]
# planner(state) -> proposed actions
PlanFn = Callable[[AgentState], Awaitable[list[AgentAction]]]


@dataclass
class AgentStep:
    modules: list[str]
    new_findings: int
    rationale: str = ""

    def to_dict(self) -> dict:
        return {"modules": self.modules, "new_findings": self.new_findings, "rationale": self.rationale}


@dataclass
class AgentReport:
    target: str
    dry_run: bool
    plan: list[AgentAction] = field(default_factory=list)
    steps: list[AgentStep] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    stopped_reason: str = ""

    @property
    def modules_run(self) -> list[str]:
        return [m for s in self.steps for m in s.modules]

    def summary(self) -> str:
        if self.dry_run:
            return f"planned {len(self.plan)} action(s) for {self.target} (dry-run — nothing executed)"
        return (
            f"{self.target}: ran {len(self.modules_run)} module(s) over {len(self.steps)} step(s), "
            f"{len(self.findings)} finding(s) — {self.stopped_reason}"
        )

    def to_dict(self) -> dict:
        return {
            "target": self.target, "dry_run": self.dry_run,
            "summary": self.summary(),
            "plan": [a.to_dict() for a in self.plan],
            "steps": [s.to_dict() for s in self.steps],
            "findings": self.findings,
            "stopped_reason": self.stopped_reason,
        }


class AgentRunner:
    def __init__(
        self, target: str, catalog: dict[str, ToolSpec], *, aggressiveness: str = "normal",
        max_steps: int = 3, planner: PlanFn | None = None, execute_fn: ExecuteFn | None = None,
        api_key: str | None = None, model: str | None = None,
    ) -> None:
        self.target = target
        self.catalog = catalog
        self.aggressiveness = aggressiveness
        self.max_steps = max(1, max_steps)
        self._planner = planner
        self._execute = execute_fn
        self._api_key = api_key
        self._model = model

    async def _plan(self, state: AgentState) -> list[AgentAction]:
        if self._planner is not None:
            actions = await self._planner(state)
        else:
            kwargs = {"model": self._model} if self._model else {}
            actions = await plan_actions(state, self.catalog, self._api_key, **kwargs)
        # Defense in depth: re-validate every action against the allow-list.
        return [a for a in actions if validate_action(a, self.catalog)]

    def _fresh_modules(self, actions: list[AgentAction], executed: set[str]) -> list[str]:
        out: list[str] = []
        for a in actions:
            if a.tool not in executed and a.tool not in out:
                out.append(a.tool)
        return out

    async def run(self, *, dry_run: bool = True) -> AgentReport:
        state = AgentState(self.target, self.aggressiveness, self.max_steps)
        plan = await self._plan(state)
        if dry_run:
            return AgentReport(self.target, True, plan=plan, stopped_reason="dry-run (nothing executed)")
        if self._execute is None:
            raise ValueError("live run requires an execute_fn")

        report = AgentReport(self.target, False, plan=plan)
        current = plan
        executed: set[str] = set()
        for i in range(self.max_steps):
            state.step = i + 1
            modules = self._fresh_modules(current, executed)
            if not modules:
                report.stopped_reason = "planner signaled done (no new modules)"
                break
            new = await self._execute(modules, state) or []
            executed.update(modules)
            state.executed = sorted(executed)
            state.findings.extend(new)
            report.steps.append(AgentStep(modules, len(new), current[0].rationale if current else ""))
            current = await self._plan(state)
        else:
            report.stopped_reason = f"reached max-steps ({self.max_steps})"
        report.findings = state.findings
        return report


__all__ = ["AgentRunner", "AgentReport", "AgentStep"]
