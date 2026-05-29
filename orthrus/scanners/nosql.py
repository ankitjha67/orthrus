"""NoSQL injection scanner (error-based).

Sends NoSQL-breaking payloads (operator objects, stray quotes/braces) into every
injection point and flags responses that leak a NoSQL driver error — the same
low-false-positive approach the SQLi scanner uses for SQL errors. A baseline is
checked first so endpoints that error on *any* input are skipped.

Operator/behavioral injection (e.g. ``user[$ne]=``) is a natural follow-up; this
module ships the high-signal error-based detector first.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from orthrus.scanners._injection import injection_points, send, used_url
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register

SCANNER_NAME = "nosql-injection"
MAX_PROBES = 80

_BASELINE = "orthrusbaseline1"

# Payloads that break NoSQL query parsing / smuggle operators.
_PAYLOADS: tuple[str, ...] = (
    "'",
    '"',
    '{"$gt":""}',
    "';return true;var x='",
    "\\",
)

# Substrings that mark a NoSQL driver / query error.
_NOSQL_ERRORS: tuple[str, ...] = (
    "mongoerror",
    "mongoservererror",
    "mongonetworkerror",
    "bsonerror",
    "casterror",
    "e11000",
    "unknown top level operator",
    "unknown operator",
    "$where",
    "failed to parse",
    "couldn't parse",
    "unexpected token in nosql",
    "elemmatch",
)


def detect_nosql_error(body: str) -> bool:
    """True if the response body reveals a NoSQL driver/query error."""
    low = body.lower()
    return any(sig in low for sig in _NOSQL_ERRORS)


@register
class NoSqlInjectionScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "nosql-injection"
    min_aggressiveness = Aggressiveness.NORMAL

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        probes = 0
        for point in injection_points(ctx):
            if probes >= MAX_PROBES:
                break
            probes += 1

            baseline = await send(ctx, point, _BASELINE)
            if baseline is not None and detect_nosql_error(baseline.text):
                continue  # endpoint errors on benign input -> not a reliable signal

            for payload in _PAYLOADS:
                resp = await send(ctx, point, payload)
                if resp is None or not detect_nosql_error(resp.text):
                    continue
                yield Finding(
                    vuln_type="nosql-injection",
                    title=f"NoSQL injection (error-based) in '{point.param}'",
                    severity=Severity.HIGH,
                    confidence=Confidence.FIRM,
                    url=used_url(point, payload),
                    parameter=point.param,
                    param_location=point.location,
                    description=(
                        f"The parameter '{point.param}' reflected a NoSQL driver error when sent a "
                        "query-breaking payload. This indicates user input is concatenated into a "
                        "NoSQL query (e.g. MongoDB), allowing authentication bypass, data "
                        "exfiltration via operator injection ($ne/$gt/$regex), or $where JavaScript "
                        "execution."
                    ),
                    remediation=(
                        "Use parameterized queries / the driver's typed query API, reject "
                        "object-valued parameters where a scalar is expected, and validate input "
                        "types server-side. Disable $where / server-side JavaScript."
                    ),
                    cwe="CWE-943",
                    scanner=SCANNER_NAME,
                    evidence=Evidence(
                        request_raw=f"{point.param}={payload}",
                        notes="NoSQL driver error reflected in response",
                    ),
                )
                break


__all__ = ["NoSqlInjectionScanner", "detect_nosql_error"]
