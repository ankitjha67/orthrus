"""OS command injection scanner (PRD §6.8 Command Injection).

Output-based: chain ``echo <canary>`` via shell metacharacters and look for the
canary alone in the response (execution), distinguishing it from mere reflection
of the payload. Time-based (aggressive only): chain a sleep and measure delay.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import AsyncIterator

from hydra.core.context import ScanContext
from hydra.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from hydra.scanners._injection import InjectionPoint, injection_points, send, used_url
from hydra.scanners.base_scanner import BaseScanner
from hydra.scanners.registry import register

SCANNER_NAME = "cmd-injection"
MAX_POINTS = 120
SLEEP_SECONDS = 5


def _output_payloads(value: str, canary: str) -> list[str]:
    cmd = f"echo {canary}"
    return [
        f"{value}; {cmd}",
        f"{value}| {cmd}",
        f"{value}&& {cmd}",
        f"{value}& {cmd}",
        f"{value}`{cmd}`",
        f"{value}$({cmd})",
        f"{value}%0a{cmd}",
    ]


def _time_payloads(value: str) -> list[str]:
    return [
        f"{value}; sleep {SLEEP_SECONDS}",
        f"{value}| sleep {SLEEP_SECONDS}",
        f"{value}& ping -n {SLEEP_SECONDS + 1} 127.0.0.1",
        f"{value}&& ping -n {SLEEP_SECONDS + 1} 127.0.0.1",
    ]


def cmd_executed(canary: str, body: str) -> bool:
    """Canary present as command *output*, not just a reflected ``echo <canary>``."""
    return canary in body and f"echo {canary}" not in body


def _param_value(point: InjectionPoint) -> str:
    for p in point.endpoint.params:
        if p.name == point.param:
            return p.value or "1"
    return "1"


@register
class CommandInjectionScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "cmd-injection"
    min_aggressiveness = Aggressiveness.NORMAL

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        aggressive = ctx.config.aggressiveness == Aggressiveness.AGGRESSIVE
        count = 0
        for point in injection_points(ctx):
            if count >= MAX_POINTS:
                break
            count += 1
            value = _param_value(point)

            finding = await self._output_based(ctx, point, value)
            if finding is None and aggressive:
                finding = await self._time_based(ctx, point, value)
            if finding is not None:
                yield finding

    async def _output_based(
        self, ctx: ScanContext, point: InjectionPoint, value: str
    ) -> Finding | None:
        canary = "HYDRA" + secrets.token_hex(4).upper()
        for payload in _output_payloads(value, canary):
            resp = await send(ctx, point, payload)
            if resp is None:
                continue
            if cmd_executed(canary, resp.text):
                return Finding(
                    vuln_type="cmd-injection",
                    title=f"OS command injection (output-based) in '{point.param}'",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.FIRM,
                    url=used_url(point, payload),
                    parameter=point.param,
                    param_location=point.location,
                    description=(
                        f"Parameter '{point.param}' is passed to an OS shell; an injected echo "
                        "command executed and its output was returned. This is remote code "
                        "execution."
                    ),
                    remediation=(
                        "Avoid invoking shells with user input. Use argument arrays / native APIs "
                        "and strict allow-list validation; never pass user data to a shell string."
                    ),
                    cwe="CWE-78",
                    scanner=SCANNER_NAME,
                    evidence=Evidence(
                        request_raw=f"{point.param}={payload}",
                        matched_at=canary,
                        notes="echo canary returned as command output",
                    ),
                )
        return None

    async def _time_based(
        self, ctx: ScanContext, point: InjectionPoint, value: str
    ) -> Finding | None:
        start = time.monotonic()
        baseline = await send(ctx, point, value)
        baseline_elapsed = time.monotonic() - start
        if baseline is None:
            return None
        for payload in _time_payloads(value):
            start = time.monotonic()
            resp = await send(ctx, point, payload)
            elapsed = time.monotonic() - start
            if resp is None:
                continue
            if elapsed >= baseline_elapsed + SLEEP_SECONDS * 0.6:
                return Finding(
                    vuln_type="cmd-injection",
                    title=f"OS command injection (time-based) in '{point.param}'",
                    severity=Severity.HIGH,
                    confidence=Confidence.FIRM,
                    url=used_url(point, payload),
                    parameter=point.param,
                    param_location=point.location,
                    description=(
                        f"Parameter '{point.param}' appears to execute OS commands; an injected "
                        f"sleep delayed the response by {elapsed:.1f}s (baseline "
                        f"{baseline_elapsed:.1f}s)."
                    ),
                    remediation=(
                        "Avoid invoking shells with user input. Use argument arrays / native APIs "
                        "and strict allow-list validation; never pass user data to a shell string."
                    ),
                    cwe="CWE-78",
                    scanner=SCANNER_NAME,
                    evidence=Evidence(
                        request_raw=f"{point.param}={payload}",
                        notes=f"response delayed {elapsed:.1f}s vs baseline {baseline_elapsed:.1f}s",
                    ),
                )
        return None


__all__ = ["CommandInjectionScanner", "cmd_executed"]
