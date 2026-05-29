"""Spec-driven endpoint extraction (OpenAPI/Swagger/GraphQL/HAR/Postman)."""

from __future__ import annotations

from orthrus.core.schemas import HttpMethod, ParamLocation
from orthrus.recon.spec_parsers import (
    detect_format,
    load_endpoints,
    parse_graphql_introspection,
    parse_har,
    parse_openapi,
    parse_postman,
)


def _by_url(eps, method, url):
    return next(e for e in eps if e.method.value == method and e.url == url)


# --------------------------------------------------------------- format sniff
def test_detect_format():
    assert detect_format({"openapi": "3.0.0", "paths": {}}) == "openapi3"
    assert detect_format({"swagger": "2.0", "paths": {}}) == "swagger2"
    assert detect_format({"data": {"__schema": {}}}) == "graphql"
    assert detect_format({"log": {"entries": []}}) == "har"
    assert detect_format({"info": {"name": "x"}, "item": []}) == "postman"
    assert detect_format("not a dict") == "unknown"


# ------------------------------------------------------------------- OpenAPI 3
def test_openapi3_json_body_and_query_and_path():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.h.com/v1"}],
        "paths": {
            "/users/{id}": {
                "get": {
                    "parameters": [
                        {"name": "id", "in": "path", "schema": {"type": "integer"}},
                        {"name": "verbose", "in": "query", "schema": {"type": "boolean"}},
                    ]
                },
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/User"}
                            }
                        }
                    }
                },
            }
        },
        "components": {
            "schemas": {
                "User": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}, "age": {"type": "integer"}},
                }
            }
        },
    }
    eps = parse_openapi(spec, "https://api.h.com/openapi.json")
    assert len(eps) == 2

    get_ep = _by_url(eps, "GET", "https://api.h.com/v1/users/1?verbose=true")
    locs = {(p.name, p.location) for p in get_ep.params}
    assert ("id", ParamLocation.PATH) in locs
    assert ("verbose", ParamLocation.QUERY) in locs

    post_ep = _by_url(eps, "POST", "https://api.h.com/v1/users/1")
    json_params = {(p.name, p.location) for p in post_ep.params}
    assert json_params == {("name", ParamLocation.JSON), ("age", ParamLocation.JSON)}
    assert post_ep.source == "api-spec"


def test_openapi3_relative_server_resolves_against_base():
    spec = {
        "openapi": "3.1.0",
        "servers": [{"url": "/api"}],
        "paths": {"/ping": {"get": {}}},
    }
    eps = parse_openapi(spec, "http://target.local:8080/openapi.json")
    assert eps[0].url == "http://target.local:8080/api/ping"


def test_openapi3_server_variables_substituted():
    spec = {
        "openapi": "3.0.0",
        "servers": [
            {
                "url": "https://{host}/v2",
                "variables": {"host": {"default": "api.h.com"}},
            }
        ],
        "paths": {"/x": {"get": {}}},
    }
    eps = parse_openapi(spec, "https://api.h.com/spec")
    assert eps[0].url == "https://api.h.com/v2/x"


# ------------------------------------------------------------------- Swagger 2
def test_swagger2_body_param_and_formdata():
    spec = {
        "swagger": "2.0",
        "host": "api.h.com",
        "basePath": "/v1",
        "schemes": ["https"],
        "paths": {
            "/login": {
                "post": {
                    "parameters": [
                        {
                            "name": "body",
                            "in": "body",
                            "schema": {"$ref": "#/definitions/Creds"},
                        },
                        {"name": "remember", "in": "query", "type": "boolean"},
                    ]
                }
            }
        },
        "definitions": {
            "Creds": {"properties": {"email": {"type": "string"}, "password": {"type": "string"}}}
        },
    }
    eps = parse_openapi(spec, "https://api.h.com/v2/api-docs")
    ep = _by_url(eps, "POST", "https://api.h.com/v1/login?remember=true")
    locs = {(p.name, p.location) for p in ep.params}
    assert ("email", ParamLocation.JSON) in locs
    assert ("password", ParamLocation.JSON) in locs
    assert ("remember", ParamLocation.QUERY) in locs


def test_swagger2_host_falls_back_to_base_url():
    spec = {"swagger": "2.0", "paths": {"/health": {"get": {}}}}
    eps = parse_openapi(spec, "http://10.0.0.5:9000/v2/api-docs")
    assert eps[0].url == "http://10.0.0.5:9000/health"


def test_path_level_parameters_apply_to_all_verbs():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://h"}],
        "paths": {
            "/items/{id}": {
                "parameters": [{"name": "id", "in": "path", "schema": {"type": "integer"}}],
                "get": {},
                "delete": {},
            }
        },
    }
    eps = parse_openapi(spec, "https://h/spec")
    assert {e.method for e in eps} == {HttpMethod.GET, HttpMethod.DELETE}
    for e in eps:
        assert any(p.name == "id" and p.location == ParamLocation.PATH for p in e.params)


# --------------------------------------------------------------------- GraphQL
def test_graphql_introspection_to_endpoints():
    doc = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "types": [
                    {
                        "name": "Query",
                        "fields": [{"name": "users", "args": [{"name": "id"}]}],
                    },
                    {
                        "name": "Mutation",
                        "fields": [{"name": "login", "args": []}],
                    },
                ],
            }
        }
    }
    eps = parse_graphql_introspection(doc, "http://h/graphql")
    assert len(eps) == 2
    assert all(e.method == HttpMethod.POST and e.url == "http://h/graphql" for e in eps)
    queries = {e.params[0].value for e in eps}
    assert "query { users(id: null) }" in queries
    assert "mutation { login }" in queries
    assert all(e.params[0].location == ParamLocation.JSON for e in eps)


def test_graphql_empty_when_no_schema():
    assert parse_graphql_introspection({"data": {}}, "http://h/graphql") == []


# ------------------------------------------------------------------------- HAR
def test_har_json_post_and_query_get():
    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "http://h/rest/user/login",
                        "postData": {
                            "mimeType": "application/json",
                            "text": '{"email":"a","password":"b"}',
                        },
                    }
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "http://h/rest/products/search?q=apple",
                    }
                },
            ]
        }
    }
    eps = parse_har(har)
    login = _by_url(eps, "POST", "http://h/rest/user/login")
    assert {(p.name, p.location) for p in login.params} == {
        ("email", ParamLocation.JSON),
        ("password", ParamLocation.JSON),
    }
    assert login.source == "har"
    search = _by_url(eps, "GET", "http://h/rest/products/search?q=apple")
    assert ("q", ParamLocation.QUERY) in {(p.name, p.location) for p in search.params}


def test_har_urlencoded_params_without_text():
    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "http://h/login",
                        "postData": {
                            "mimeType": "application/x-www-form-urlencoded",
                            "params": [
                                {"name": "user", "value": "a"},
                                {"name": "pass", "value": "b"},
                            ],
                        },
                    }
                }
            ]
        }
    }
    eps = parse_har(har)
    ep = _by_url(eps, "POST", "http://h/login")
    assert {(p.name, p.location) for p in ep.params} == {
        ("user", ParamLocation.BODY),
        ("pass", ParamLocation.BODY),
    }


# --------------------------------------------------------------------- Postman
def test_postman_nested_folders_and_raw_json():
    collection = {
        "info": {"name": "demo"},
        "item": [
            {
                "name": "auth",
                "item": [
                    {
                        "name": "login",
                        "request": {
                            "method": "POST",
                            "url": {
                                "raw": "http://h/rest/user/login",
                                "protocol": "http",
                                "host": ["h"],
                                "path": ["rest", "user", "login"],
                            },
                            "body": {
                                "mode": "raw",
                                "raw": '{"email":"a","password":"b"}',
                                "options": {"raw": {"language": "json"}},
                            },
                        },
                    }
                ],
            },
            {
                "name": "search",
                "request": {
                    "method": "GET",
                    "url": "http://h/rest/products/search?q=apple",
                },
            },
        ],
    }
    eps = parse_postman(collection)
    login = _by_url(eps, "POST", "http://h/rest/user/login")
    assert {(p.name, p.location) for p in login.params} == {
        ("email", ParamLocation.JSON),
        ("password", ParamLocation.JSON),
    }
    assert login.source == "postman"
    search = _by_url(eps, "GET", "http://h/rest/products/search?q=apple")
    assert ("q", ParamLocation.QUERY) in {(p.name, p.location) for p in search.params}


def test_postman_url_object_with_query_list():
    collection = {
        "info": {"name": "demo"},
        "item": [
            {
                "name": "q",
                "request": {
                    "method": "GET",
                    "url": {
                        "protocol": "https",
                        "host": ["api", "h", "com"],
                        "path": ["search"],
                        "query": [{"key": "term", "value": "x"}],
                    },
                },
            }
        ],
    }
    eps = parse_postman(collection)
    assert eps[0].url == "https://api.h.com/search?term=x"


# ------------------------------------------------------------ top-level loader
def test_load_endpoints_autodetects_and_accepts_raw_json():
    raw = '{"openapi":"3.0.0","servers":[{"url":"https://h"}],"paths":{"/p":{"get":{}}}}'
    eps = load_endpoints(raw, "https://h/spec")
    assert eps[0].url == "https://h/p"


def test_load_endpoints_unknown_returns_empty():
    assert load_endpoints('{"random":"doc"}', "http://h") == []
    assert load_endpoints("not json at all", "http://h") == []
