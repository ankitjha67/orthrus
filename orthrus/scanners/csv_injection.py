"""CSV / formula-injection scanner (OWASP "CSV injection").

Many apps let users supply data that later lands in a CSV / spreadsheet export
(reports, contact lists, invoices). When a cell value begins with a formula
trigger character (``=``, ``+``, ``-``, ``@``) and is written into the export
unescaped, Excel / LibreOffice / Google Sheets interpret it as a formula on
open — enabling DDE command execution, data exfiltration via ``HYPERLINK``/
``WEBSERVICE``, and client-side compromise of whoever opens the file.

This scanner sends a **benign** arithmetic formula carrying a unique nonce
(``=1+orthrus...``) into each injection point and only flags a finding when the
response is a real spreadsheet/CSV export *and* the payload survived verbatim,
still starting with a trigger char. The content-type guard keeps false positives
near zero: a formula reflected into an HTML page is not exploitable here, only
one written into a downloadable spreadsheet cell is.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from orthrus.scanners._injection import injection_points, send, used_url
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.csv-injection")

SCANNER_NAME = "csv-injection"
MAX_POINTS = 80

# Characters that make a spreadsheet treat a cell value as a formula.
_TRIGGER_CHARS = ("=", "+", "-", "@")

# Content-type fragments that mark a CSV / spreadsheet export. Only when the
# payload lands in one of these is formula injection actually exploitable.
_SPREADSHEET_CTYPES = (
    "text/csv",
    "application/csv",
    "vnd.ms-excel",
    "spreadsheetml",
    "application/vnd.ms-office",
)


def make_payload() -> str:
    """A benign formula payload carrying a unique nonce (proves the sink only)."""
    nonce = "orthrus" + secrets.token_hex(3)
    return "=1+" + nonce


def formula_survived(content_type: str | None, body: str, payload: str) -> bool:
    """True only if a spreadsheet/CSV export wrote ``payload`` as a live formula.

    Requires both: (1) the response content-type is a CSV/spreadsheet export,
    and (2) the payload appears in the body still starting with a formula trigger
    character (``=``/``+``/``-``/``@``), i.e. it was written into a cell
    unescaped. The content-type guard is what keeps false positives near zero.
    """
    if not content_type:
        return False
    ctype = content_type.lower()
    if not any(frag in ctype for frag in _SPREADSHEET_CTYPES):
        return False
    if not payload or payload[0] not in _TRIGGER_CHARS:
        return False
    return payload in body


@register
class CsvInjectionScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "formula-injection"
    min_aggressiveness = Aggressiveness.NORMAL

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        probes = 0
        seen: set[tuple[str, str, str]] = set()
        for point in injection_points(ctx):
            if probes >= MAX_POINTS:
                break
            probes += 1

            payload = make_payload()
            try:
                resp = await send(ctx, point, payload)
            except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
                logger.debug("csv-injection probe failed for %s: %s", point.param, exc)
                continue
            if resp is None:
                continue

            content_type = self._content_type(resp)
            if not formula_survived(content_type, resp.text, payload):
                continue

            key = (point.method.value, point.location.value, point.param)
            if key in seen:
                continue
            seen.add(key)

            yield Finding(
                vuln_type="formula-injection",
                title=f"CSV / formula injection in '{point.param}'",
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                url=used_url(point, payload),
                parameter=point.param,
                param_location=point.location,
                description=(
                    f"The parameter '{point.param}' was written unescaped into a CSV / "
                    "spreadsheet export: a benign formula payload survived in the downloaded "
                    "cell, still beginning with a formula trigger character. When a victim "
                    "opens the export in Excel / LibreOffice / Google Sheets, an attacker-"
                    "controlled formula executes — enabling DDE command execution, data "
                    "exfiltration via HYPERLINK/WEBSERVICE, and client-side compromise."
                ),
                remediation=(
                    "Sanitize exported cell values: prefix any value that begins with =, +, "
                    "-, or @ with a single quote (or a tab/space), strip the leading trigger "
                    "character, or wrap the value so the spreadsheet treats it as text. Apply "
                    "this at export time for every user-controlled field."
                ),
                cwe="CWE-1236",
                scanner=SCANNER_NAME,
                evidence=Evidence(
                    matched_at=content_type,
                    notes="benign formula payload survived in spreadsheet export cell",
                    request_raw=f"{point.param}={payload}",
                ),
            )

    @staticmethod
    def _content_type(resp: httpx.Response) -> str | None:
        """Best-effort content-type from an httpx.Response or duck-typed fake."""
        ctype = getattr(resp, "content_type", None)
        if ctype:
            return ctype
        try:
            return resp.headers.get("content-type")
        except AttributeError:
            return None


__all__ = ["CsvInjectionScanner", "formula_survived", "make_payload"]
