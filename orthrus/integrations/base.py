"""External-tool adapter framework.

Each adapter wraps a best-of-breed CLI tool (nuclei, sqlmap, ffuf, amass, …),
runs it as a subprocess, and normalises its output into ORTHRUS ``Finding``
objects. Adapters are opt-in via ``--tools`` and only run when their binary is
present (``orthrus doctor`` reports availability).

Safety note: external tools do **not** route through the scope-enforced
HttpClient, so per-request scope cannot be guaranteed for them. As a guardrail
the adapter scope-checks the target URL before launching, and tools are
invoked against the single target only — but the operator is responsible for
the tool's own targeting. This is the same deliberate trade-off as the raw-socket
request-smuggling probe.
"""

from __future__ import annotations

import asyncio
import shutil
from abc import ABC, abstractmethod
from collections.abc import Iterable

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Finding
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("integrations")

TOOL_REGISTRY: dict[str, type[ExternalToolAdapter]] = {}


def register_tool(cls: type[ExternalToolAdapter]) -> type[ExternalToolAdapter]:
    TOOL_REGISTRY[cls.name] = cls
    return cls


def get_tools(names: Iterable[str]) -> list[ExternalToolAdapter]:
    """Instantiate adapters for the requested names ('all' selects every adapter)."""
    selected = {n.strip().lower() for n in names if n and n.strip()}
    if "all" in selected:
        classes = list(TOOL_REGISTRY.values())
    else:
        classes = [cls for name, cls in TOOL_REGISTRY.items() if name in selected]
    return [cls() for cls in classes]


def available_tools() -> dict[str, bool]:
    """Map every registered tool name -> whether its binary is on PATH."""
    return {name: shutil.which(cls.binary) is not None for name, cls in TOOL_REGISTRY.items()}


class ExternalToolAdapter(ABC):
    name: str = "tool"
    binary: str = ""
    default_timeout: float = 300.0

    def available(self) -> bool:
        return bool(self.binary) and shutil.which(self.binary) is not None

    @abstractmethod
    def build_command(self, target: str) -> list[str]:
        """Argv (including the binary) to run the tool against ``target``."""
        raise NotImplementedError

    @abstractmethod
    def parse_output(self, stdout: str, target: str) -> list[Finding]:
        """Normalise the tool's stdout into Findings (pure; unit-tested)."""
        raise NotImplementedError

    async def run(self, ctx: ScanContext) -> list[Finding]:
        target = ctx.config.target
        if not self.available():
            logger.info("tool '%s': binary %r not found on PATH — skipping", self.name, self.binary)
            return []
        try:
            if not ctx.scope.is_allowed(target):
                logger.warning("tool '%s': target out of scope — skipping", self.name)
                return []
        except ScopeViolation:
            return []
        stdout = await self._exec(self.build_command(target), self.default_timeout)
        if stdout is None:
            return []
        return self.parse_output(stdout, target)

    async def _exec(self, cmd: list[str], timeout_s: float) -> str | None:
        """Run argv, return stdout text, or None on failure/timeout."""
        proc: asyncio.subprocess.Process | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, _err = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
            return out.decode("utf-8", "ignore")
        except (FileNotFoundError, OSError, ValueError) as exc:
            logger.warning("tool '%s' could not start: %s", self.name, exc)
            return None
        except TimeoutError:
            logger.warning("tool '%s' timed out after %.0fs", self.name, timeout_s)
            if proc is not None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            return None


__all__ = ["ExternalToolAdapter", "TOOL_REGISTRY", "register_tool", "get_tools", "available_tools"]
