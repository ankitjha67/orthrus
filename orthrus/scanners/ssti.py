"""Server-side template injection scanner (PRD §6.8 SSTI).

Injects polyglot arithmetic in several template syntaxes ({{a*b}}, ${a*b},
#{a*b}, <%= a*b %>, ${{a*b}}). If the *product* appears in the response while
the literal expression does not, the template engine evaluated our input.
Random factors per probe make coincidental matches negligible.
"""

from __future__ import annotations

import random
from collections.abc import AsyncIterator

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from orthrus.scanners._injection import injection_points, send, used_url
from orthrus.scanners._payloads import ssti_templates
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register

SCANNER_NAME = "ssti"
MAX_POINTS = 120


def _templates(expr: str) -> list[tuple[str, str]]:
    return ssti_templates(expr)


def ssti_evaluated(expected: str, raw_expr: str, body: str) -> bool:
    """True if the product is present but the raw expression is not (i.e. evaluated)."""
    return expected in body and raw_expr not in body


@register
class SstiScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "ssti"
    min_aggressiveness = Aggressiveness.NORMAL

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        count = 0
        for point in injection_points(ctx):
            if count >= MAX_POINTS:
                break
            count += 1
            a = random.randint(1000, 9999)
            b = random.randint(1000, 9999)
            expr = f"{a}*{b}"
            expected = str(a * b)

            for engine, payload in _templates(expr):
                resp = await send(ctx, point, payload)
                if resp is None:
                    continue
                if ssti_evaluated(expected, expr, resp.text):
                    yield Finding(
                        vuln_type="ssti",
                        title=f"Server-side template injection ({engine}) in '{point.param}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.FIRM,
                        url=used_url(point, payload),
                        parameter=point.param,
                        param_location=point.location,
                        description=(
                            f"Parameter '{point.param}' is evaluated by a server-side template "
                            f"engine ({engine}): the expression {expr} returned {expected}. "
                            "SSTI commonly leads to remote code execution."
                        ),
                        remediation=(
                            "Never pass user input into template source. Use logic-less templates "
                            "or sandboxed rendering and pass user data only as bound variables."
                        ),
                        cwe="CWE-1336",
                        scanner=SCANNER_NAME,
                        evidence=Evidence(
                            request_raw=f"{point.param}={payload}",
                            matched_at=expected,
                            notes=f"{expr} evaluated to {expected}",
                        ),
                    )
                    break


__all__ = ["SstiScanner", "ssti_evaluated"]
