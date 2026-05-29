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
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger

logger = get_logger("scanner.sqli")

SCANNER_NAME = "sqli"
MAX_POINTS = 120

ERROR_PAYLOADS = ["'", '"', "')", "';", "\"))", "`"]

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

TIME_PAYLOADS = [
    ("MySQL", "' AND SLEEP({n})-- -"),
    ("PostgreSQL", "' AND (SELECT 1 FROM PG_SLEEP({n}))-- -"),
    ("Microsoft SQL Server", "'; WAITFOR DELAY '0:0:{n}'-- -"),
]
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
    """TRUE response should resemble baseline; FALSE response should diverge."""
    return _similar(baseline, true_resp) and not _similar(true_resp, false_resp)


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

            finding = await self._error_based(ctx, point, value)
            if finding is None:
                finding = await self._boolean_based(ctx, point, value, baseline_text, aggressive)
            if finding is None and aggressive:
                finding = await self._time_based(ctx, point, value, baseline_elapsed)

            if finding is not None:
                yield finding

    async def _error_based(
        self, ctx: ScanContext, point: InjectionPoint, value: str
    ) -> Finding | None:
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
        true_base = f"{value}' AND '1'='1"
        false_base = f"{value}' AND '1'='2"
        # Each pair is (evasion-label, TRUE payload, FALSE payload). The raw pair
        # is always tried first; under AGGRESSIVE we additionally try transport-
        # surviving evasions (mixed case, comment spacing) of the same clause so a
        # signature WAF that blocks the plain "AND '1'='1" can't mask the finding.
        pairs: list[tuple[str, str, str]] = [("raw", true_base, false_base)]
        if aggressive:
            t_vars = transport_safe_variants(true_base)
            f_vars = transport_safe_variants(false_base)
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


__all__ = ["SqlInjectionScanner", "detect_sql_error", "boolean_injectable"]
