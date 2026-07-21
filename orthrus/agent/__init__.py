"""Autonomous authorized-pentest orchestrator (`orthrus agent`).

A bounded LLM planner that sequences ORTHRUS's existing scope-enforced,
non-destructive tools - recon and scanners - against an authorized target. Its
action space is a hard allow-list built from the scanner registry: no shells, no
arbitrary code, no way to reach out of scope (every tool goes through the
scope-enforced client). ``--dry-run`` shows the plan without executing.
"""

from __future__ import annotations

from orthrus.agent.planner import (
    AgentAction,
    AgentState,
    ToolSpec,
    build_catalog,
    deterministic_plan,
    plan_actions,
    validate_action,
)
from orthrus.agent.runner import AgentReport, AgentRunner, AgentStep

__all__ = [
    "AgentAction",
    "AgentState",
    "ToolSpec",
    "build_catalog",
    "deterministic_plan",
    "plan_actions",
    "validate_action",
    "AgentRunner",
    "AgentReport",
    "AgentStep",
]
