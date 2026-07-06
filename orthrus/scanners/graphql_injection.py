"""GraphQL-aware injection scanner (closes the DVGA-class coverage gap).

The generic SQLi/command/SSTI scanners fuzz HTTP query/body parameters — they
never reach arguments nested inside GraphQL operations. Most of a GraphQL app's
real attack surface (DVGA's SQLi, OS command injection, template injection) lives
in *mutation/query arguments*, so this scanner:

1. finds & confirms a GraphQL endpoint,
2. runs introspection and parses the schema,
3. enumerates every Query/Mutation field argument of a String/ID scalar type,
4. injects an error-based SQLi probe, an OS-command canary, and an SSTI
   arithmetic probe into each argument via a real GraphQL operation, and
5. flags a finding when the sink proves the injection *in band* — a DBMS error,
   the command canary echoed back (without its ``echo`` prefix), or the template
   arithmetic evaluated (product present, literal absent).

All probes are read-only in intent and bounded; confirmation (fresh-nonce
re-proof) is the job of ``exploits/graphql_injection_confirm.py``.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.graphql import COMMON_PATHS, TYPENAME_QUERY, confirms_graphql
from orthrus.scanners.registry import register
from orthrus.scanners.sqli import detect_sql_error
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.graphql-injection")

SCANNER_NAME = "graphql-injection"
MAX_POINTS = 40  # cap injectable (field, arg) points probed per endpoint

INTROSPECT = {
    "query": (
        "query{__schema{queryType{name} mutationType{name} "
        "types{kind name fields{name "
        "args{name type{kind name ofType{kind name ofType{kind name}}}} "
        "type{kind name ofType{kind name}}}}}}"
    )
}

# Injection probes. Payloads deliberately avoid the double-quote character so they
# embed cleanly inside a GraphQL double-quoted string argument.
_SQLI_PAYLOAD = "orthrus_gql'"
_CMD_TOKEN = "ORTHRUSGQLCMD9174"
_CMD_PAYLOAD = f"; echo {_CMD_TOKEN}"
_SSTI_PRODUCT = "1022117"  # 1009 * 1013 — distinctive, collision-unlikely
_SSTI_PAYLOADS = ("{{1009*1013}}", "${1009*1013}", "#{1009*1013}")


def _named_type(node: dict | None) -> tuple[str | None, str | None]:
    """Follow a GraphQL type's ``ofType`` wrappers (NON_NULL/LIST) to the named
    underlying type; return ``(kind, name)``."""
    seen = 0
    while isinstance(node, dict) and node.get("name") is None and node.get("ofType") and seen < 8:
        node = node["ofType"]
        seen += 1
    if isinstance(node, dict):
        return node.get("kind"), node.get("name")
    return None, None


def injectable_points(schema: dict) -> Iterator[tuple[str, str, str, bool]]:
    """Yield ``(operation, field, arg, needs_subselection)`` for every Query/Mutation
    field argument whose type is a String/ID scalar."""
    root = schema.get("__schema") if isinstance(schema, dict) else None
    if not isinstance(root, dict):
        return
    op_of = {}
    for key, op in (("queryType", "query"), ("mutationType", "mutation")):
        name = (root.get(key) or {}).get("name") if isinstance(root.get(key), dict) else None
        if name:
            op_of[name] = op
    for type_def in root.get("types") or []:
        operation = op_of.get(type_def.get("name"))
        if not operation:
            continue
        for field in type_def.get("fields") or []:
            ret_kind, _ = _named_type(field.get("type"))
            needs_sub = ret_kind in ("OBJECT", "INTERFACE", "UNION")
            for arg in field.get("args") or []:
                _, arg_name = _named_type(arg.get("type"))
                if arg_name in ("String", "ID"):
                    yield operation, field["name"], arg["name"], needs_sub


def _operation(op: str, field: str, arg: str, payload: str, needs_sub: bool) -> dict:
    esc = payload.replace("\\", "\\\\").replace('"', '\\"')
    sub = " {__typename}" if needs_sub else ""
    return {"query": f'{op}{{ {field}({arg}: "{esc}"){sub} }}'}


def command_injected(body: str) -> bool:
    """Canary echoed back *without* its ``echo`` prefix ⇒ the command ran (not reflected)."""
    return _CMD_TOKEN in body and f"echo {_CMD_TOKEN}" not in body


def template_evaluated(body: str, literal: str) -> bool:
    """Arithmetic product present and the literal expression absent ⇒ SSTI evaluated."""
    return _SSTI_PRODUCT in body and literal not in body


@register
class GraphqlInjectionScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "graphql-injection"
    min_aggressiveness = Aggressiveness.NORMAL  # active injection

    def _candidates(self, ctx: ScanContext) -> list[str]:
        base = urlsplit(ctx.config.target)
        root = f"{base.scheme}://{base.netloc}"
        urls = [root + path for path in COMMON_PATHS]
        urls += [ep.url for ep in ctx.endpoints if "graphql" in urlsplit(ep.url).path.lower()]
        seen: set[str] = set()
        out: list[str] = []
        for url in urls:
            if url not in seen and ctx.scope.is_allowed(url):
                seen.add(url)
                out.append(url)
        return out

    async def _post(self, ctx: ScanContext, url: str, payload: object) -> str | None:
        try:
            resp = await ctx.http.post(url, json=payload, follow_redirects=False)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("graphql-injection probe failed for %s: %s", url, exc)
            return None
        return resp.text

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        for url in self._candidates(ctx):
            intro = await self._post(ctx, url, INTROSPECT)
            if intro is None or not confirms_graphql(intro):
                # Not a GraphQL endpoint, or a stray 200 — probe once more, then bail.
                tn = await self._post(ctx, url, TYPENAME_QUERY)
                if tn is None or '"__typename"' not in tn:
                    continue
            try:
                schema = json.loads(intro).get("data") if intro else None
            except (ValueError, TypeError, AttributeError):
                schema = None
            if not isinstance(schema, dict):
                continue  # introspection disabled/unavailable → nothing to enumerate

            points = list(injectable_points(schema))[:MAX_POINTS]
            for operation, field, arg, needs_sub in points:
                async for finding in self._probe(ctx, url, operation, field, arg, needs_sub):
                    yield finding

    async def _probe(
        self, ctx: ScanContext, url: str, operation: str, field: str, arg: str, needs_sub: bool
    ) -> AsyncIterator[Finding]:
        loc = f"{operation} {field}({arg})"

        # 1. Error-based SQL injection.
        body = await self._post(ctx, url, _operation(operation, field, arg, _SQLI_PAYLOAD, needs_sub))
        dbms = detect_sql_error(body) if body else None
        if dbms:
            yield self._finding(
                "sqli", Severity.HIGH, "CWE-89", url, loc,
                f"SQL injection in GraphQL argument '{field}.{arg}'",
                f"Injecting a single quote into the GraphQL argument '{arg}' of "
                f"'{operation} {field}' produced a {dbms} database error, so the argument is "
                "concatenated into a SQL query unsanitised — SQL injection via GraphQL.",
                "Use parameterised queries / an ORM for values derived from GraphQL arguments; "
                "never build SQL by string-concatenating resolver inputs.",
                _operation(operation, field, arg, _SQLI_PAYLOAD, needs_sub), f"{dbms} error",
            )
            return  # one class per point is enough signal

        # 2. OS command injection (canary echo).
        body = await self._post(ctx, url, _operation(operation, field, arg, _CMD_PAYLOAD, needs_sub))
        if body and command_injected(body):
            yield self._finding(
                "cmd-injection", Severity.CRITICAL, "CWE-78", url, loc,
                f"OS command injection in GraphQL argument '{field}.{arg}'",
                f"A shell metacharacter + canary injected into the GraphQL argument '{arg}' of "
                f"'{operation} {field}' was executed — the canary was echoed back by the OS shell, "
                "proving arbitrary command execution via a GraphQL resolver.",
                "Never pass GraphQL argument values to a shell; use argument-vector process APIs "
                "with a fixed command and strict allow-listing of inputs.",
                _operation(operation, field, arg, _CMD_PAYLOAD, needs_sub), f"canary {_CMD_TOKEN} echoed",
            )
            return

        # 3. Server-side template injection (arithmetic evaluated).
        for payload in _SSTI_PAYLOADS:
            body = await self._post(ctx, url, _operation(operation, field, arg, payload, needs_sub))
            if body and template_evaluated(body, payload):
                yield self._finding(
                    "ssti", Severity.HIGH, "CWE-1336", url, loc,
                    f"Server-side template injection in GraphQL argument '{field}.{arg}'",
                    f"A template expression injected into the GraphQL argument '{arg}' of "
                    f"'{operation} {field}' was evaluated server-side (arithmetic computed), "
                    "indicating server-side template injection reachable through GraphQL.",
                    "Do not render GraphQL argument values through a server-side template engine; "
                    "treat resolver inputs as data, not template source.",
                    _operation(operation, field, arg, payload, needs_sub), f"evaluated to {_SSTI_PRODUCT}",
                )
                return

    def _finding(
        self, subtype: str, severity: Severity, cwe: str, url: str, loc: str,
        title: str, description: str, remediation: str, request: dict, matched: str,
    ) -> Finding:
        return Finding(
            vuln_type="graphql-injection",
            title=title,
            severity=severity,
            confidence=Confidence.FIRM,
            url=url,
            parameter=loc,
            description=description,
            remediation=remediation,
            cwe=cwe,
            scanner=SCANNER_NAME,
            evidence=Evidence(request_raw=str(request), matched_at=matched,
                              notes=f"GraphQL {subtype} via {loc}"),
        )


__all__ = [
    "GraphqlInjectionScanner",
    "injectable_points",
    "command_injected",
    "template_evaluated",
    "_named_type",
    "_operation",
    "INTROSPECT",
]
