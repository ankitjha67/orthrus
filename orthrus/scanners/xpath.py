"""XPath / XQuery injection scanner (error-based).

Sends XPath-expression-breaking payloads (stray quotes, unbalanced brackets and
parentheses) into every injection point and flags responses that leak an XPath
evaluation error — the same low-false-positive, error-based approach the SQLi,
NoSQL and LDAP scanners use. A baseline is checked first so endpoints that error
on *any* input are skipped.

Boolean/blind XPath (e.g. ``' or '1'='1``) is a natural follow-up; this module
ships the high-signal error-based detector first.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from orthrus.scanners._injection import injection_points, send, used_url
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register

SCANNER_NAME = "xpath-injection"
MAX_PROBES = 80

_BASELINE = "orthrusbaseline1"

# Payloads that break XPath/XQuery expression parsing.
_PAYLOADS: tuple[str, ...] = (
    "'",
    '"',
    "]",
    ")",
    "' or '1'='1",
    "count(/*)",
)

# Substrings that mark an XPath/XQuery evaluation error across common stacks.
_XPATH_ERRORS: tuple[str, ...] = (
    "xpathexception",
    "xpathevaluationexception",
    "javax.xml.xpath",
    "org.apache.xpath",
    "system.xml.xpath",
    "ms.internal.xml",
    "xmlxpatheval",  # libxml2 xmlXPathEval
    "xpath_eval",  # PHP xpath_eval / DOMXPath
    "simplexmlelement::xpath",
    "warning: xpath",
    "invalid xpath",
    "invalid expression",
    "invalid predicate",
    "a closing bracket expected",
    "expression must evaluate to a node-set",
    "unfinished literal",
    "syntaxerror: invalid expression",  # lxml
)


def detect_xpath_error(body: str) -> bool:
    """True if the response body reveals an XPath/XQuery evaluation error."""
    low = body.lower()
    return any(sig in low for sig in _XPATH_ERRORS)


@register
class XPathInjectionScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "xpath-injection"
    min_aggressiveness = Aggressiveness.NORMAL

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        probes = 0
        for point in injection_points(ctx):
            if probes >= MAX_PROBES:
                break
            probes += 1

            baseline = await send(ctx, point, _BASELINE)
            if baseline is not None and detect_xpath_error(baseline.text):
                continue  # endpoint errors on benign input -> not a reliable signal

            for payload in _PAYLOADS:
                resp = await send(ctx, point, payload)
                if resp is None or not detect_xpath_error(resp.text):
                    continue
                yield Finding(
                    vuln_type="xpath-injection",
                    title=f"XPath injection (error-based) in '{point.param}'",
                    severity=Severity.HIGH,
                    confidence=Confidence.FIRM,
                    url=used_url(point, payload),
                    parameter=point.param,
                    param_location=point.location,
                    description=(
                        f"The parameter '{point.param}' reflected an XPath evaluation error when "
                        "sent an expression-breaking payload. This indicates user input is "
                        "concatenated into an XPath/XQuery query over an XML document, enabling "
                        "authentication bypass and extraction of the entire XML store via blind "
                        "boolean injection."
                    ),
                    remediation=(
                        "Use parameterized XPath (variable binding via XPathExpression / "
                        "setXPathVariableResolver) instead of string concatenation, and validate "
                        "input against an allow-list."
                    ),
                    cwe="CWE-643",
                    scanner=SCANNER_NAME,
                    evidence=Evidence(
                        request_raw=f"{point.param}={payload}",
                        notes="XPath evaluation error reflected in response",
                    ),
                )
                break


__all__ = ["XPathInjectionScanner", "detect_xpath_error"]
