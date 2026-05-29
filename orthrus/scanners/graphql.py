"""GraphQL scanner (PRD §6.8 GraphQL).

Locates GraphQL endpoints (common paths + crawled hits) and runs a battery of
GraphQL-specific tests modelled on DVGA (Damn Vulnerable GraphQL Application):

* **Introspection** — a schema-dumping introspection query that leaks the API.
* **Field-suggestion leakage** — graphql-core/js suggest valid field names in
  error messages ("Did you mean ...") *even when introspection is disabled*,
  re-enabling schema discovery one field at a time.
* **Query batching** — the server accepts a JSON array of operations and
  returns an array of results, enabling auth brute-force + request amplification.
* **Alias overloading** — the server resolves an unbounded number of aliases of
  the same field in one request, the basis of an alias-amplification DoS.
* **Debug / stack-trace disclosure** — server errors leak Python tracebacks or
  internal stack frames (DVGA runs Flask in debug mode).

All probes are read-only and bounded (a handful of requests per confirmed
endpoint); the DoS checks *demonstrate* the amplification primitive with a
modest payload rather than actually flooding the target.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.graphql")

SCANNER_NAME = "graphql"

COMMON_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/graphql/console",
    "/graphiql",
    "/query",
    "/api/graphql/v1",
]

INTROSPECTION_QUERY = {"query": "query{__schema{queryType{name} types{name}}}"}
TYPENAME_QUERY = {"query": "{__typename}"}

# A deliberately invalid root field — servers that leak suggestions answer with
# "Cannot query field \"<x>\" on type \"Query\". Did you mean \"...\"?".
_SUGGEST_PROBE_FIELD = "orthrusInvalidFieldZzz"
SUGGESTION_PROBE = {"query": "query{" + _SUGGEST_PROBE_FIELD + "}"}

# Alias-overloading proof: N aliases of __typename in one request. Resolving all
# of them confirms the server does work proportional to alias count (no cost cap).
ALIAS_PROBE_COUNT = 100
_ALIAS_PREFIX = "orthrusAlias"
ALIAS_PROBE = {
    "query": "{" + " ".join(f"{_ALIAS_PREFIX}{i}:__typename" for i in range(ALIAS_PROBE_COUNT)) + "}"
}

_SUGGEST_RE = re.compile(r"Did you mean[^\"']*[\"']([A-Za-z_][A-Za-z0-9_]*)")


def introspection_enabled(body: str) -> bool:
    return '"__schema"' in body or '"queryType"' in body


def is_graphql_response(body: str) -> bool:
    markers = ("Cannot query field", "Must provide query", "GraphQL", '"errors"')
    return any(m in body for m in markers)


def confirms_graphql(body: str) -> bool:
    """A body that proves the endpoint really speaks GraphQL (not a stray 200)."""
    return introspection_enabled(body) or '"__typename"' in body or is_graphql_response(body)


def suggestion_leak(body: str) -> str | None:
    """Return the field name a 'Did you mean' error leaked, else ``None``.

    This is the introspection-disabled bypass: the validator suggests real
    schema fields close to the (invalid) field we asked for.
    """
    match = _SUGGEST_RE.search(body)
    return match.group(1) if match else None


def batching_enabled(body: str) -> bool:
    """True when the body is a JSON array of >=2 GraphQL results (batching on)."""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return False
    if not isinstance(data, list) or len(data) < 2:
        return False
    return all(isinstance(item, dict) and ("data" in item or "errors" in item) for item in data)


def resolved_alias_count(body: str) -> int:
    """Count resolved ``orthrusAlias*`` keys in a GraphQL ``data`` object."""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return 0
    payload = data.get("data") if isinstance(data, dict) else None
    if not isinstance(payload, dict):
        return 0
    return sum(1 for key in payload if key.startswith(_ALIAS_PREFIX))


def stack_trace_leak(body: str) -> bool:
    """True when a GraphQL error body leaks an internal stack trace / debug page."""
    if "Traceback (most recent call last)" in body:
        return True
    if "werkzeug.debug" in body or "Werkzeug Debugger" in body:
        return True
    # A located GraphQLError with a file path + line number is a strong signal.
    return 'File "/' in body and ("line " in body or ".py" in body)


@register
class GraphqlScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "graphql"

    def _candidates(self, ctx: ScanContext) -> list[str]:
        base = urlsplit(ctx.config.target)
        root = f"{base.scheme}://{base.netloc}"
        urls = [root + path for path in COMMON_PATHS]
        urls += [ep.url for ep in ctx.endpoints if "graphql" in urlsplit(ep.url).path.lower()]
        seen: set[str] = set()
        unique: list[str] = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                unique.append(url)
        return unique

    async def _post(self, ctx: ScanContext, url: str, payload: object) -> str | None:
        try:
            resp = await ctx.http.post(url, json=payload, follow_redirects=False)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("graphql probe failed for %s: %s", url, exc)
            return None
        return resp.text

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        for url in self._candidates(ctx):
            if not ctx.scope.is_allowed(url):
                continue

            intro_body = await self._post(ctx, url, INTROSPECTION_QUERY)
            if intro_body is None:
                continue

            # Confirm this is really a GraphQL endpoint before deeper probing, so
            # we never fire the DoS/suggestion battery at an unrelated handler.
            confirmed = confirms_graphql(intro_body)
            if not confirmed:
                typename_body = await self._post(ctx, url, TYPENAME_QUERY)
                if typename_body is None or '"__typename"' not in typename_body:
                    continue
                confirmed = True

            intro_on = introspection_enabled(intro_body)
            if intro_on:
                yield Finding(
                    vuln_type="graphql",
                    title="GraphQL introspection enabled",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    url=url,
                    description=(
                        "The GraphQL endpoint answered an introspection query, exposing its full "
                        "schema (types, queries, mutations). This aids attackers in mapping the API."
                    ),
                    remediation=(
                        "Disable introspection in production and restrict GraphQL debugging "
                        "interfaces (GraphiQL/Playground)."
                    ),
                    cwe="CWE-200",
                    scanner=SCANNER_NAME,
                    evidence=Evidence(
                        request_raw=str(INTROSPECTION_QUERY),
                        matched_at="__schema",
                    ),
                )
            else:
                yield Finding(
                    vuln_type="graphql",
                    title="GraphQL endpoint detected (introspection disabled)",
                    severity=Severity.INFO,
                    confidence=Confidence.FIRM,
                    url=url,
                    description="A GraphQL endpoint was found; introspection appears disabled.",
                    remediation="Ensure the endpoint enforces auth, depth limits, and rate limiting.",
                    cwe="CWE-200",
                    scanner=SCANNER_NAME,
                    evidence=Evidence(notes="GraphQL error/response markers present"),
                )

            async for finding in self._deep_probes(ctx, url, intro_on):
                yield finding

    async def _deep_probes(
        self, ctx: ScanContext, url: str, intro_on: bool
    ) -> AsyncIterator[Finding]:
        # 1. Field-suggestion leakage — most impactful when introspection is OFF.
        suggest_body = await self._post(ctx, url, SUGGESTION_PROBE)
        if suggest_body is not None:
            leaked = suggestion_leak(suggest_body)
            if leaked is not None:
                sev = Severity.LOW if intro_on else Severity.MEDIUM
                yield Finding(
                    vuln_type="graphql",
                    title="GraphQL field-suggestion leakage",
                    severity=sev,
                    confidence=Confidence.FIRM,
                    url=url,
                    description=(
                        "Invalid-field errors suggest real schema field names "
                        f'(e.g. "{leaked}"). An attacker can reconstruct the schema field-by-field '
                        "even when introspection is disabled."
                    ),
                    remediation=(
                        "Disable field suggestions in production (e.g. graphql-core "
                        "validation 'did you mean' hints) and return generic errors."
                    ),
                    cwe="CWE-200",
                    scanner=SCANNER_NAME,
                    evidence=Evidence(
                        request_raw=str(SUGGESTION_PROBE),
                        matched_at="Did you mean",
                        notes=f"server suggested field '{leaked}'",
                    ),
                )

        # 2. Query batching — array of operations accepted.
        batch_payload = [TYPENAME_QUERY, TYPENAME_QUERY]
        batch_body = await self._post(ctx, url, batch_payload)
        if batch_body is not None and batching_enabled(batch_body):
            yield Finding(
                vuln_type="graphql-dos",
                title="GraphQL query batching enabled",
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                url=url,
                description=(
                    "The endpoint accepted a JSON array of operations and returned an array of "
                    "results. Batching lets an attacker pack many operations into one request — "
                    "amplifying rate-limited actions (e.g. login/OTP brute-force) and resource use."
                ),
                remediation=(
                    "Disable query batching, or enforce a per-request operation cap and apply "
                    "rate limiting against the aggregate, not per HTTP request."
                ),
                cwe="CWE-770",
                scanner=SCANNER_NAME,
                evidence=Evidence(
                    request_raw=str(batch_payload),
                    matched_at="batched array response",
                ),
            )

        # 3. Alias overloading — many aliases of one field resolved in one request.
        alias_body = await self._post(ctx, url, ALIAS_PROBE)
        if alias_body is not None:
            count = resolved_alias_count(alias_body)
            if count >= ALIAS_PROBE_COUNT:
                yield Finding(
                    vuln_type="graphql-dos",
                    title="GraphQL alias overloading (no query-cost limit)",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    url=url,
                    description=(
                        f"The endpoint resolved all {count} aliases of a single field in one "
                        "request with no cost/complexity limit. An attacker can multiply server "
                        "work arbitrarily within one query — an alias-amplification DoS primitive."
                    ),
                    remediation=(
                        "Enforce query cost analysis / complexity limits and cap the number of "
                        "aliased fields per request (e.g. graphql-query-complexity, depth limits)."
                    ),
                    cwe="CWE-770",
                    scanner=SCANNER_NAME,
                    evidence=Evidence(
                        request_raw=f"{ALIAS_PROBE_COUNT} aliases of __typename",
                        matched_at=f"{count} aliases resolved",
                    ),
                )

        # 4. Debug / stack-trace disclosure on a malformed operation.
        if suggest_body is not None and stack_trace_leak(suggest_body):
            yield Finding(
                vuln_type="graphql",
                title="GraphQL debug / stack-trace disclosure",
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                url=url,
                description=(
                    "A GraphQL error response leaked an internal stack trace / debug page, "
                    "exposing source paths and framework internals (server running in debug mode)."
                ),
                remediation=(
                    "Disable debug mode in production and strip stack traces from GraphQL error "
                    "responses; return generic error messages."
                ),
                cwe="CWE-209",
                scanner=SCANNER_NAME,
                evidence=Evidence(matched_at="Traceback / debug page in error body"),
            )


__all__ = [
    "GraphqlScanner",
    "introspection_enabled",
    "is_graphql_response",
    "confirms_graphql",
    "suggestion_leak",
    "batching_enabled",
    "resolved_alias_count",
    "stack_trace_leak",
]
