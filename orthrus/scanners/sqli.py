"""SQL injection scanner (PRD §6.2).

Detection methods:
  - error-based: DBMS error signatures appear after injecting quote/syntax chars
  - boolean-based blind: TRUE payload resembles baseline while FALSE diverges
  - time-based blind: SLEEP/WAITFOR payloads cause a measurable delay (aggressive only)

Confirmation (data extraction via sqlmap/custom) is the Phase-4 job of
exploits/sqli_confirm.py; this scanner only detects.
"""

from __future__ import annotations

import re
import time
from collections.abc import AsyncIterator

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from orthrus.scanners._evasion import transport_safe_variants
from orthrus.scanners._injection import InjectionPoint, injection_points, send, used_url
from orthrus.scanners._payloads import SQLI_BOOLEAN_PAIRS, SQLI_ERROR, SQLI_TIME
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger

logger = get_logger("scanner.sqli")

SCANNER_NAME = "sqli"
MAX_POINTS = 120

ERROR_PAYLOADS = SQLI_ERROR

# DBMS -> error-signature regexes (case-insensitive).
_SQL_ERROR_SIGNATURES: dict[str, list[str]] = {
    "MySQL": [
        r"SQL syntax.*MySQL",
        r"Warning.*\bmysqli?_",
        r"MySqlException",
        r"valid MySQL result",
        r"check the manual that corresponds to your (MySQL|MariaDB) server version",
        r"MySQLSyntaxErrorException",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR",
        r"Warning.*\bpg_",
        r"valid PostgreSQL result",
        r"PG::SyntaxError",
        r"unterminated quoted string at or near",
    ],
    "Microsoft SQL Server": [
        r"Driver.* SQL[ _-]*Server",
        r"OLE DB.* SQL Server",
        r"\bSQL Server[^&<]*Driver",
        r"Warning.*\bmssql_",
        r"Unclosed quotation mark after the character string",
        r"System\.Data\.SqlClient\.SqlException",
    ],
    "Oracle": [
        r"\bORA-\d{5}",
        r"Oracle error",
        r"Oracle.*Driver",
        r"quoted string not properly terminated",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"sqlite3\.OperationalError",
        r"unrecognized token:",
        r"SQL logic error",
    ],
}

_COMPILED = {
    dbms: [re.compile(p, re.IGNORECASE) for p in pats]
    for dbms, pats in _SQL_ERROR_SIGNATURES.items()
}

TIME_PAYLOADS = SQLI_TIME
SLEEP_SECONDS = 4


def detect_sql_error(body: str) -> str | None:
    """Return the DBMS name whose error signature appears, else None."""
    for dbms, patterns in _COMPILED.items():
        if any(p.search(body) for p in patterns):
            return dbms
    return None


def _similar(a: str, b: str, tolerance: float = 0.05) -> bool:
    la, lb = len(a), len(b)
    if max(la, lb) == 0:
        return True
    return abs(la - lb) / max(la, lb) <= tolerance


def boolean_injectable(baseline: str, true_resp: str, false_resp: str) -> bool:
    """Boolean-based blind signal.

    The TRUE and FALSE payloads differ only in a SQL truth value (``1=1`` vs
    ``1=2``), so a *divergence* between their responses can only come from the
    database evaluating that condition. We additionally require that at least one
    side still resembles the un-injected baseline - a cheap guard against random
    page-to-page variation. Crucially we do **not** require the TRUE side
    specifically to match the baseline: ``OR 1=1`` returns *more* rows than the
    baseline, and a ``-- -`` comment that truncates a second parameter also makes
    TRUE diverge - both real injections the old "TRUE must equal baseline" rule
    silently missed.
    """
    if _similar(true_resp, false_resp):
        return False
    return _similar(baseline, true_resp) or _similar(baseline, false_resp)


def error_status_signal(baseline_status: int, odd_quote_status: int, even_quote_status: int) -> bool:
    """Broken/fixed-quote error signal.

    A single (odd) quote breaks the SQL string and errors the request (5xx),
    while a balanced (even) quote parses cleanly and does not - a strong
    error-based-blind SQLi signal even when the error page leaks no DBMS text.
    The even-quote control is what keeps this low-false-positive: an app that
    500s on *any* quote fails the control and is not flagged.
    """
    return baseline_status < 500 <= odd_quote_status and even_quote_status < 500


def _param_value(point: InjectionPoint) -> str:
    for p in point.endpoint.params:
        if p.name == point.param:
            return p.value or "1"
    return "1"


def _finding(
    point: InjectionPoint,
    title: str,
    technique: str,
    confidence: Confidence,
    payload: str,
    evidence_note: str,
) -> Finding:
    return Finding(
        vuln_type="sqli",
        title=title,
        severity=Severity.HIGH,
        confidence=confidence,
        url=used_url(point, payload),
        parameter=point.param,
        param_location=point.location,
        description=(
            f"Parameter '{point.param}' appears injectable via {technique}. "
            "An attacker may be able to read or modify database contents."
        ),
        remediation=(
            "Use parameterized queries / prepared statements; never concatenate user input "
            "into SQL. Apply least-privilege DB accounts and input validation."
        ),
        cwe="CWE-89",
        scanner=SCANNER_NAME,
        evidence=Evidence(request_raw=f"{point.param}={payload}", notes=evidence_note),
    )


@register
class SqlInjectionScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "sqli"
    min_aggressiveness = Aggressiveness.NORMAL

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        aggressive = ctx.config.aggressiveness == Aggressiveness.AGGRESSIVE
        count = 0
        for point in injection_points(ctx):
            if count >= MAX_POINTS:
                break
            count += 1
            value = _param_value(point)

            start = time.monotonic()
            baseline = await send(ctx, point, value)
            baseline_elapsed = time.monotonic() - start
            if baseline is None:
                continue
            baseline_text = baseline.text
            if detect_sql_error(baseline_text):
                continue  # error already present unprovoked -> skip to avoid false positives

            finding = await self._error_based(ctx, point, value, baseline.status_code)
            if finding is None:
                finding = await self._boolean_based(ctx, point, value, baseline_text, aggressive)
            if finding is None and aggressive:
                finding = await self._time_based(ctx, point, value, baseline_elapsed)

            if finding is not None:
                yield finding

    async def _error_based(
        self, ctx: ScanContext, point: InjectionPoint, value: str, baseline_status: int = 200
    ) -> Finding | None:
        # (1) Broken/fixed-quote status differential: a single quote breaks the SQL
        # string (5xx) while a balanced quote parses cleanly - catches error-based
        # SQLi whose error page leaks no DBMS text (e.g. a generic 500).
        odd = await send(ctx, point, value + "'")
        if odd is not None and baseline_status < 500 <= odd.status_code:
            even = await send(ctx, point, value + "''")
            if even is not None and error_status_signal(
                baseline_status, odd.status_code, even.status_code
            ):
                return _finding(
                    point,
                    f"SQL injection (error-based, broken/fixed quote) in parameter '{point.param}'",
                    "error-based injection (quote-break status differential)",
                    Confidence.FIRM,
                    value + "'",
                    f"a single quote returned HTTP {odd.status_code} while a balanced quote "
                    f"returned HTTP {even.status_code} (baseline HTTP {baseline_status}) - the "
                    "quote breaks the SQL string",
                )

        # (2) DBMS error text signatures.
        for payload in ERROR_PAYLOADS:
            resp = await send(ctx, point, value + payload)
            if resp is None:
                continue
            dbms = detect_sql_error(resp.text)
            if dbms:
                return _finding(
                    point,
                    f"SQL injection (error-based, {dbms}) in parameter '{point.param}'",
                    "error-based injection",
                    Confidence.FIRM,
                    value + payload,
                    f"{dbms} error signature returned after injecting {payload!r}",
                )
        return None

    async def _boolean_based(
        self,
        ctx: ScanContext,
        point: InjectionPoint,
        value: str,
        baseline_text: str,
        aggressive: bool = False,
    ) -> Finding | None:
        # Try several closing contexts (string/numeric/parenthesised/double-quote)
        # so a backend query whose syntax doesn't match one style is still caught
        # by another. Each entry is (label, TRUE payload, FALSE payload).
        pairs: list[tuple[str, str, str]] = [
            (label, f"{value}{true_suffix}", f"{value}{false_suffix}")
            for label, true_suffix, false_suffix in SQLI_BOOLEAN_PAIRS
        ]
        # Under AGGRESSIVE, additionally try transport-surviving evasions (mixed
        # case, comment spacing) of the canonical string clause, so a signature
        # WAF that blocks the plain "AND '1'='1" can't mask the finding.
        if aggressive:
            t_vars = transport_safe_variants(f"{value}' AND '1'='1")
            f_vars = transport_safe_variants(f"{value}' AND '1'='2")
            for (label, t_enc), (_, f_enc) in zip(t_vars[1:], f_vars[1:], strict=False):
                pairs.append((label, t_enc, f_enc))

        for label, true_payload, false_payload in pairs:
            true_resp = await send(ctx, point, true_payload)
            false_resp = await send(ctx, point, false_payload)
            if true_resp is None or false_resp is None:
                continue
            if boolean_injectable(baseline_text, true_resp.text, false_resp.text):
                note = "TRUE payload matched baseline while FALSE payload diverged"
                if label != "raw":
                    note += f" (via {label} WAF-evasion encoding)"
                return _finding(
                    point,
                    f"SQL injection (boolean-based blind) in parameter '{point.param}'",
                    "boolean-based blind injection",
                    Confidence.TENTATIVE,
                    true_payload,
                    note,
                )
        return None

    async def _time_based(
        self, ctx: ScanContext, point: InjectionPoint, value: str, baseline_elapsed: float
    ) -> Finding | None:
        for dbms, template in TIME_PAYLOADS:
            payload = value + template.format(n=SLEEP_SECONDS)
            start = time.monotonic()
            resp = await send(ctx, point, payload)
            elapsed = time.monotonic() - start
            if resp is None:
                continue
            if elapsed >= baseline_elapsed + SLEEP_SECONDS * 0.6:
                return _finding(
                    point,
                    f"SQL injection (time-based blind, {dbms}) in parameter '{point.param}'",
                    "time-based blind injection",
                    Confidence.FIRM,
                    payload,
                    f"response delayed {elapsed:.1f}s vs baseline {baseline_elapsed:.1f}s",
                )
        return None


__all__ = ["SqlInjectionScanner", "detect_sql_error", "boolean_injectable", "error_status_signal"]
