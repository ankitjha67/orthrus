"""Tests for GraphQL introspection/response detection + deep (DVGA-style) probes."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.scanners.graphql import (
    ALIAS_PROBE_COUNT,
    GraphqlScanner,
    batching_enabled,
    confirms_graphql,
    fragment_cycle_rejected,
    introspection_enabled,
    is_graphql_response,
    resolved_alias_count,
    stack_trace_leak,
    suggestion_leak,
)


def test_introspection_enabled_from_schema():
    body = '{"data":{"__schema":{"queryType":{"name":"Query"}}}}'
    assert introspection_enabled(body) is True


def test_introspection_disabled():
    body = '{"errors":[{"message":"GraphQL introspection is not allowed"}]}'
    assert introspection_enabled(body) is False


def test_is_graphql_response():
    assert is_graphql_response('{"errors":[{"message":"Cannot query field x"}]}') is True


def test_not_graphql_response():
    assert is_graphql_response("<html><body>404 Not Found</body></html>") is False


# --------------------------------------------------------------- confirms_graphql
def test_confirms_graphql_via_typename():
    assert confirms_graphql('{"data":{"__typename":"Query"}}') is True


def test_confirms_graphql_false_on_plain_page():
    assert confirms_graphql("<html>hello</html>") is False


# --------------------------------------------------------------- suggestion leak
def test_suggestion_leak_extracts_field():
    body = (
        '{"errors":[{"message":"Cannot query field \\"systemHealt\\" on type '
        '\\"Query\\". Did you mean \\"systemHealth\\"?"}]}'
    )
    assert suggestion_leak(body) == "systemHealth"


def test_suggestion_leak_none_when_absent():
    assert suggestion_leak('{"errors":[{"message":"Syntax Error"}]}') is None


# --------------------------------------------------------------- batching
def test_batching_enabled_array_of_results():
    body = '[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]'
    assert batching_enabled(body) is True


def test_batching_disabled_single_object():
    assert batching_enabled('{"data":{"__typename":"Query"}}') is False


def test_batching_disabled_single_element_array():
    assert batching_enabled('[{"data":{"__typename":"Query"}}]') is False


# --------------------------------------------------------------- alias overloading
def test_resolved_alias_count_counts_prefixed_keys():
    payload = ",".join(f'"orthrusAlias{i}":"Query"' for i in range(ALIAS_PROBE_COUNT))
    body = '{"data":{' + payload + "}}"
    assert resolved_alias_count(body) == ALIAS_PROBE_COUNT


def test_resolved_alias_count_zero_on_error():
    assert resolved_alias_count('{"errors":[{"message":"too complex"}]}') == 0


# --------------------------------------------------------------- stack-trace leak
def test_stack_trace_leak_traceback():
    body = 'Traceback (most recent call last):\n  File "/app/server.py", line 42'
    assert stack_trace_leak(body) is True


def test_stack_trace_leak_clean_error():
    assert stack_trace_leak('{"errors":[{"message":"Cannot query field x"}]}') is False


# --------------------------------------------------------------- circular fragment
def test_fragment_cycle_rejected_true():
    body = '{"errors":[{"message":"Cannot spread fragment \\"frA\\" within itself via frB."}]}'
    assert fragment_cycle_rejected(body) is True


def test_fragment_cycle_rejected_false_when_executed():
    assert fragment_cycle_rejected('{"data":{"__typename":"Query"}}') is False


# --------------------------------------------------------------- full scan flow
class _FakeResp:
    def __init__(self, text: str) -> None:
        self.text = text


class _DvgaHttp:
    """Simulates a DVGA-style endpoint at /graphql: introspection OFF, but
    leaking suggestions + a traceback, with batching and alias overloading on."""

    def __init__(self) -> None:
        self.posts: list[object] = []

    async def post(self, url: str, json: object = None, **kw: object) -> _FakeResp:
        self.posts.append(json)
        if not url.endswith("/graphql"):
            return _FakeResp("<html>404 Not Found</html>")
        if isinstance(json, list):  # batch probe
            return _FakeResp('[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]')
        query = json.get("query", "") if isinstance(json, dict) else ""
        if "__schema" in query:  # introspection probe -> disabled, but confirms GraphQL
            return _FakeResp('{"errors":[{"message":"GraphQL introspection is disabled"}]}')
        if "orthrusAlias" in query:  # alias-overloading probe -> all resolved
            payload = ",".join(f'"orthrusAlias{i}":"Query"' for i in range(ALIAS_PROBE_COUNT))
            return _FakeResp('{"data":{' + payload + "}}")
        if "orthrusInvalidFieldZzz" in query:  # suggestion probe -> leak + traceback
            return _FakeResp(
                '{"errors":[{"message":"Cannot query field \\"orthrusInvalidFieldZzz\\" on type '
                '\\"Query\\". Did you mean \\"systemHealth\\"?"}]}\n'
                'Traceback (most recent call last):\n  File "/app/core/server.py", line 10'
            )
        return _FakeResp('{"data":{"__typename":"Query"}}')


def _scan_ctx(http: object) -> SimpleNamespace:
    return SimpleNamespace(
        endpoints=[],
        http=http,
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(target="http://h/"),
    )


async def test_full_scan_surfaces_dvga_vulns():
    findings = [f async for f in GraphqlScanner().scan(_scan_ctx(_DvgaHttp()))]
    titles = {f.title for f in findings}
    # introspection is OFF, so we should NOT claim it's enabled...
    assert "GraphQL introspection enabled" not in titles
    # ...but every deeper DVGA-style weakness should surface:
    assert "GraphQL field-suggestion leakage" in titles
    assert "GraphQL query batching enabled" in titles
    assert "GraphQL alias overloading (no query-cost limit)" in titles
    assert "GraphQL debug / stack-trace disclosure" in titles
    # the DVGA fake executes the circular fragment (no cycle rejection) -> flagged
    assert "GraphQL accepts circular fragments (recursion DoS)" in titles
    # DoS findings carry the dedicated vuln_type for accurate CVSS/availability scoring.
    assert {f.vuln_type for f in findings if "batching" in f.title} == {"graphql-dos"}
