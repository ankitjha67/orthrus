"""Tests for GraphQL introspection/response detection."""

from __future__ import annotations

from orthrus.scanners.graphql import introspection_enabled, is_graphql_response


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
