"""Business-logic probes: parameter tampering + HTTP parameter pollution (PRD §6.7).

True business-logic flaws - broken multi-step workflows, price manipulation that
actually ships goods for free, coupon/loyalty abuse - need an application model a
scanner does not have, so this module is *honestly scoped*. It automates the two
mechanical, high-signal precursors that frequently expose weak server-side
validation and reports them as TENTATIVE for manual confirmation:

1. Parameter tampering - value-bearing numeric params (price / amount / quantity
   / balance …) are resent with out-of-band values (negative, zero, fractional,
   overflow). To keep false positives down the probe first proves the endpoint
   *does* validate input by sending garbage and confirming a rejection; only then
   does an accepted negative/zero value count as a missing range/sign check.

2. HTTP parameter pollution - a query key is sent twice with two distinct,
   reflected sentinels. If exactly one sentinel survives in the response (and
   which one is order-dependent), the server silently drops a duplicate, so a
   control that inspects the *other* occurrence (a WAF, an auth filter, an input
   validator) can be bypassed by smuggling the real value in the dropped copy.

Both probes are non-destructive: they mutate an existing request's inputs and
read the response, always through the scope-enforced HttpClient. No resource is
created or deleted (DELETE/price-commit side effects are never triggered).
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import (
    Aggressiveness,
    Confidence,
    Evidence,
    Finding,
    ParamLocation,
    Severity,
)
from orthrus.scanners._injection import InjectionPoint, injection_points, send, used_url
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.encoding import with_duplicate_query_param
from orthrus.utils.scope import ScopeViolation
from orthrus.utils.sensitivity import describe, scan_sensitive

SCANNER_NAME = "business-logic"

MAX_TAMPER_PROBES = 60
MAX_HPP_PROBES = 60

# Param-name hints that mark a numeric value worth tampering with.
MONETARY_HINTS: tuple[str, ...] = (
    "price",
    "amount",
    "cost",
    "total",
    "subtotal",
    "balance",
    "fee",
    "discount",
    "credit",
    "payment",
    "refund",
    "salary",
    "wage",
)
QUANTITY_HINTS: tuple[str, ...] = (
    "qty",
    "quantity",
    "count",
    "stock",
    "items",
    "unit",
    "points",
    "age",
    "weight",
)
NUMERIC_HINTS: tuple[str, ...] = MONETARY_HINTS + QUANTITY_HINTS

# A type-validated numeric field should reject this; if it doesn't, the field
# validates nothing and "accepting" a negative value tells us nothing (skip).
# Deliberately free of any rejection token so a reflected echo isn't mistaken
# for a rejection.
CONTROL_GARBAGE = "orthrusqzx"

# Substrings that mark a server-side rejection of bad input.
_REJECTION_TOKENS: tuple[str, ...] = (
    "invalid",
    "must be",
    "not allowed",
    "not permitted",
    "validation",
    "out of range",
    "too large",
    "too small",
    "negative",
    "minimum",
    "maximum",
    "positive",
    "bad request",
    "error",
    "cannot be",
    "exceeds",
    "not a valid",
    "not a number",
    "greater than",
    "less than",
)


def is_numeric(value: str) -> bool:
    """True if ``value`` is a parseable number containing at least one digit."""
    v = value.strip()
    if not any(c.isdigit() for c in v):
        return False
    try:
        float(v)
    except ValueError:
        return False
    return True


def is_tamperable(name: str, value: str) -> bool:
    """A numeric value whose param name suggests a price/quantity-like field."""
    if not is_numeric(value):
        return False
    lname = name.lower()
    return any(h in lname for h in NUMERIC_HINTS)


def is_monetary(name: str) -> bool:
    lname = name.lower()
    return any(h in lname for h in MONETARY_HINTS)


def tamper_values(value: str) -> list[tuple[str, str]]:
    """Out-of-band variants of a numeric ``value`` as (label, tampered) pairs.

    Drops any variant equal to the original so each probe is a genuine change.
    """
    candidates = [
        ("negative", "-1"),
        ("zero", "0"),
        ("fractional", "0.0001"),
        ("overflow", "999999999999"),
        ("scientific", "1e9"),  # parses as a huge float past naive int() validators
    ]
    original = value.strip()
    return [(label, v) for label, v in candidates if v != original]


def looks_like_rejection(status: int, body: str) -> bool:
    """True if the response reads as a server-side rejection of the input."""
    if status >= 400:
        return True
    low = body.lower()
    return any(tok in low for tok in _REJECTION_TOKENS)


def tampering_signal(
    baseline_status: int,
    control_status: int,
    control_body: str,
    tampered_status: int,
    tampered_body: str,
) -> bool:
    """Whether an out-of-band numeric value slipped past a field that validates.

    Requires: the legitimate value succeeded (2xx); a garbage value was *rejected*
    (so the field validates input at all - otherwise the signal is meaningless);
    and the tampered value was accepted (2xx, no rejection). That combination
    means the field checks type but not range/sign - a missing-validation flaw.
    """
    if not (200 <= baseline_status < 300):
        return False
    if not looks_like_rejection(control_status, control_body):
        return False  # endpoint validates nothing -> inconclusive, avoid FP
    if not (200 <= tampered_status < 300):
        return False
    return not looks_like_rejection(tampered_status, tampered_body)


def hpp_winner(a: str, b: str, body_a: str, body_b: str, body_dup: str) -> str | None:
    """Resolve duplicate-param precedence from two reflected sentinels.

    ``body_a``/``body_b`` are responses to the sentinels sent *alone* (used to
    confirm the param is reflected, so precedence is observable); ``body_dup`` is
    the response to ``key=a&key=b``. Returns ``"first"`` if only ``a`` survives,
    ``"last"`` if only ``b`` survives, else ``None`` (both kept / not reflected →
    no clean drop, no finding).
    """
    if a not in body_a or b not in body_b:
        return None  # param not reflected -> can't observe a dropped duplicate
    a_in = a in body_dup
    b_in = b in body_dup
    if a_in and not b_in:
        return "first"
    if b_in and not a_in:
        return "last"
    return None


def _param_value(point: InjectionPoint) -> str:
    for p in point.endpoint.params:
        if p.name == point.param and p.location == point.location:
            return p.value or ""
    return ""


@register
class BusinessLogicScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "business-logic"
    min_aggressiveness = Aggressiveness.NORMAL

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        tamper_count = 0
        hpp_count = 0
        seen_hpp: set[tuple[str, str, str]] = set()

        for point in injection_points(ctx):
            value = _param_value(point)

            if tamper_count < MAX_TAMPER_PROBES and is_tamperable(point.param, value):
                tamper_count += 1
                finding = await self._probe_tampering(ctx, point, value)
                if finding is not None:
                    yield finding

            if point.location == ParamLocation.QUERY and hpp_count < MAX_HPP_PROBES:
                key = (point.method.value, urlsplit(point.endpoint.url).path, point.param)
                if key not in seen_hpp:
                    seen_hpp.add(key)
                    hpp_count += 1
                    finding = await self._probe_hpp(ctx, point)
                    if finding is not None:
                        yield finding

    async def _probe_tampering(
        self, ctx: ScanContext, point: InjectionPoint, value: str
    ) -> Finding | None:
        baseline = await send(ctx, point, value)
        if baseline is None or not (200 <= baseline.status_code < 300):
            return None
        control = await send(ctx, point, CONTROL_GARBAGE)
        if control is None:
            return None

        monetary = is_monetary(point.param)
        accepted: list[str] = []
        money_evidence = ""
        for label, tampered in tamper_values(value):
            resp = await send(ctx, point, tampered)
            if resp is None:
                continue
            if tampering_signal(
                baseline.status_code,
                control.status_code,
                control.text,
                resp.status_code,
                resp.text,
            ):
                accepted.append(f"{label}={tampered}")
                # Impact signal: the accepted response echoes a money/balance value, so the
                # tampered amount was not just accepted but reflected downstream.
                if monetary and not money_evidence:
                    money = [h for h in scan_sensitive(resp.text) if h.kind == "money"]
                    if money:
                        money_evidence = describe(money[:3])

        if not accepted:
            return None

        shown = ", ".join(accepted)
        # A monetary field whose tampered value comes back as an amount/balance is a
        # demonstrated financial-impact bug (HIGH, firm); a monetary field that merely
        # accepts the value is a MEDIUM precursor; a non-monetary field is LOW.
        if monetary and money_evidence:
            severity, confidence = Severity.HIGH, Confidence.FIRM
        elif monetary:
            severity, confidence = Severity.MEDIUM, Confidence.TENTATIVE
        else:
            severity, confidence = Severity.LOW, Confidence.TENTATIVE
        impact = (
            f" The response reflected a monetary value ({money_evidence}) for the tampered "
            "input, so the amount is carried downstream - confirm the charge/credit."
            if money_evidence else ""
        )
        notes = (
            f"garbage value '{CONTROL_GARBAGE}' was rejected but {shown} returned 2xx "
            "without a validation error"
        )
        if money_evidence:
            notes += f"; tampered response reflected money: {money_evidence}"
        return Finding(
            vuln_type="parameter-tampering",
            title=f"Missing numeric validation on '{point.param}' (parameter tampering)",
            severity=severity,
            confidence=confidence,
            url=used_url(point, "-1"),
            parameter=point.param,
            param_location=point.location,
            description=(
                f"The numeric field '{point.param}' rejects malformed input (so it does "
                f"validate) yet accepts out-of-band values [{shown}]. A negative price, a "
                "zero/oversized quantity, or a fractional amount slipping past server-side "
                "checks is a common precursor to business-logic abuse (free or discounted "
                f"orders, inventory/limit bypass).{impact} Manually confirm the value is honored "
                "downstream (cart total, charged amount, fulfilled quantity)."
            ),
            remediation=(
                "Validate numeric inputs server-side against business rules - enforce sign, "
                "minimum/maximum range, and precision - and re-derive security-relevant "
                "values (prices, totals) from trusted server state rather than the request."
            ),
            cwe="CWE-472",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                request_raw=f"{point.param} tampered: {shown}",
                notes=notes,
            ),
        )

    async def _probe_hpp(self, ctx: ScanContext, point: InjectionPoint) -> Finding | None:
        nonce = secrets.token_hex(3)
        a = f"orthrushpp{nonce}a"
        b = f"orthrushpp{nonce}b"

        resp_a = await send(ctx, point, a)
        resp_b = await send(ctx, point, b)
        if resp_a is None or resp_b is None:
            return None

        method = point.method.value
        dup_url = with_duplicate_query_param(point.endpoint.url, point.param, a, b)
        try:
            resp_dup = await ctx.http.request(method, dup_url)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL):
            return None
        if resp_dup is None:
            return None

        winner = hpp_winner(a, b, resp_a.text, resp_b.text, resp_dup.text)
        if winner is None:
            return None

        position = "first" if winner == "first" else "last"
        return Finding(
            vuln_type="parameter-pollution",
            title=f"HTTP parameter pollution: duplicate '{point.param}' silently dropped",
            severity=Severity.LOW,
            confidence=Confidence.TENTATIVE,
            url=dup_url,
            parameter=point.param,
            param_location=ParamLocation.QUERY,
            description=(
                f"Sending '{point.param}' twice in one query string caused the server to keep "
                f"only the {position} occurrence and discard the other. When a security control "
                "(WAF rule, authorization filter, or input validator) inspects the discarded "
                "copy while application code reads the surviving one, an attacker can smuggle a "
                "malicious value past the control via the dropped duplicate."
            ),
            remediation=(
                "Reject requests containing duplicate parameter keys, or normalize them "
                "consistently across every layer (proxy, WAF, framework, application) so no "
                "component disagrees about which value is authoritative."
            ),
            cwe="CWE-235",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                request_raw=f"{point.param}={a}&{point.param}={b}",
                notes=f"server kept the {position} duplicate (sentinel {a if winner == 'first' else b})",
            ),
        )


__all__ = [
    "BusinessLogicScanner",
    "is_numeric",
    "is_tamperable",
    "is_monetary",
    "tamper_values",
    "looks_like_rejection",
    "tampering_signal",
    "hpp_winner",
    "NUMERIC_HINTS",
    "MONETARY_HINTS",
    "QUANTITY_HINTS",
]
