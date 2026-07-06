"""GraphQL-aware injection scanner + confirmer.

The fake HTTP backend is the bundled target's own vulnerable ``graphql_execute``,
so these tests exercise the real introspect → enumerate → inject → detect path.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from orthrus.core.schemas import Confidence, Finding, Severity
from orthrus.exploits.graphql_injection_confirm import GraphqlInjectionConfirm
from orthrus.scanners.graphql_injection import (
    GraphqlInjectionScanner,
    _named_type,
    command_injected,
    injectable_points,
    template_evaluated,
)
from tests.integration.reflecting_target import graphql_execute


class _Resp:
    def __init__(self, text: str) -> None:
        self.text = text


class _GqlHttp:
    """Routes POST /graphql through the deliberately-vulnerable mini executor."""

    async def post(self, url: str, json: object = None, **kw: object) -> _Resp:
        if url.endswith("/graphql"):
            return _Resp(graphql_execute(_dumps(json)))
        return _Resp("<html>404 Not Found</html>")

    async def get(self, url: str, params: dict | None = None, **kw: object) -> _Resp:
        return _Resp("<html>404</html>")


def _dumps(obj: object) -> str:
    return json.dumps(obj)


def _ctx(http: object) -> SimpleNamespace:
    return SimpleNamespace(
        endpoints=[],
        http=http,
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(target="http://h/"),
    )


# --------------------------------------------------------------- pure helpers
def test_named_type_unwraps_non_null_list():
    node = {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String"}}
    assert _named_type(node) == ("SCALAR", "String")


def test_injectable_points_finds_string_args():
    schema = {"__schema": {
        "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
        "types": [
            {"name": "Query", "fields": [
                {"name": "userByName", "args": [{"name": "name", "type": {"kind": "SCALAR", "name": "String"}}],
                 "type": {"kind": "SCALAR", "name": "String"}},
                {"name": "count", "args": [{"name": "n", "type": {"kind": "SCALAR", "name": "Int"}}],
                 "type": {"kind": "SCALAR", "name": "Int"}},
            ]},
            {"name": "Mutation", "fields": [
                {"name": "run", "args": [{"name": "cmd", "type": {"kind": "SCALAR", "name": "String"}}],
                 "type": {"kind": "SCALAR", "name": "String"}}],
            },
        ],
    }}
    pts = set(injectable_points(schema))
    assert ("query", "userByName", "name", False) in pts
    assert ("mutation", "run", "cmd", False) in pts
    assert not any(f == "count" for _, f, _, _ in pts)  # Int arg is not injectable


def test_command_injected_distinguishes_execution_from_reflection():
    assert command_injected('{"data":{"d":"ORTHRUSGQLCMD9174"}}') is True
    assert command_injected('{"data":{"d":"; echo ORTHRUSGQLCMD9174"}}') is False  # reflected only


def test_template_evaluated_requires_product_not_literal():
    assert template_evaluated('{"data":{"t":"1022117"}}', "{{1009*1013}}") is True
    assert template_evaluated('{"data":{"t":"{{1009*1013}}"}}', "{{1009*1013}}") is False


# --------------------------------------------------------------- full scan
async def test_scan_surfaces_sqli_cmd_and_ssti_via_graphql():
    findings = [f async for f in GraphqlInjectionScanner().scan(_ctx(_GqlHttp()))]
    titles = " || ".join(f.title for f in findings)
    assert "SQL injection in GraphQL argument 'userByName.name'" in titles
    assert "OS command injection in GraphQL argument 'systemDiagnostics.cmd'" in titles
    assert "template injection in GraphQL argument 'renderTemplate.tpl'" in titles
    assert all(f.vuln_type == "graphql-injection" for f in findings)
    # each carries a precise operation/field(arg) location for the confirmer
    assert all("(" in (f.parameter or "") for f in findings)


# --------------------------------------------------------------- confirmer
async def test_confirmer_reproves_sqli_with_fresh_probe():
    finding = Finding(
        vuln_type="graphql-injection",
        title="SQL injection in GraphQL argument 'userByName.name'",
        severity=Severity.HIGH, confidence=Confidence.FIRM,
        url="http://h/graphql", parameter="query userByName(name)",
    )
    finding.id = "1"
    result = await GraphqlInjectionConfirm().confirm(_ctx(_GqlHttp()), finding)
    assert result.success is True and "error" in (result.extracted_data or "")


async def test_confirmer_fails_when_not_injectable():
    finding = Finding(
        vuln_type="graphql-injection",
        title="OS command injection in GraphQL argument 'noSuchField.x'",
        severity=Severity.CRITICAL, confidence=Confidence.FIRM,
        url="http://h/graphql", parameter="mutation noSuchField(x)",
    )
    finding.id = "2"
    result = await GraphqlInjectionConfirm().confirm(_ctx(_GqlHttp()), finding)
    assert result.success is False
