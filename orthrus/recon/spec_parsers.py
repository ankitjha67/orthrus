"""Spec-driven endpoint extraction (PRD §5.2 - API discovery, machine-readable).

A static/dynamic crawler only finds the API surface a page happens to exercise.
When the target ships a machine-readable contract - an OpenAPI/Swagger document,
a GraphQL introspection result, a recorded HAR, or a Postman collection - the
*entire* declared surface is knowable up front, including JSON request bodies
and their typed fields. These pure functions turn each of those artifacts into
``Endpoint`` objects with typed params (QUERY / JSON / BODY / PATH / HEADER /
COOKIE) so the scan phase can probe the real REST/JSON API.

Everything here is offline and side-effect free (no network, no disk): callers
hand in already-parsed JSON/dicts. Fetching specs in scope is the job of the
``ApiDiscovery`` recon module, which still routes every request through the
scope-enforced HttpClient.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

from orthrus.core.browser import CapturedRequest
from orthrus.core.schemas import Endpoint, HttpMethod, Param, ParamLocation
from orthrus.recon.browser_crawl import endpoint_from_capture

# HTTP verbs that appear as keys under an OpenAPI/Swagger path item.
_OPENAPI_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")

# OpenAPI ``in:`` location -> our ParamLocation.
_IN_TO_LOCATION = {
    "query": ParamLocation.QUERY,
    "path": ParamLocation.PATH,
    "header": ParamLocation.HEADER,
    "cookie": ParamLocation.COOKIE,
    "formData": ParamLocation.BODY,  # Swagger 2.0 form fields
}

_MAX_REF_DEPTH = 8  # guard against self-referential $ref chains


# --------------------------------------------------------------------------- #
# Format detection + dispatch                                                  #
# --------------------------------------------------------------------------- #
def detect_format(doc: Any) -> str:
    """Best-effort classification of a parsed spec document."""
    if not isinstance(doc, dict):
        return "unknown"
    if "openapi" in doc:
        return "openapi3"
    if "swagger" in doc:
        return "swagger2"
    if "__schema" in doc or (isinstance(doc.get("data"), dict) and "__schema" in doc["data"]):
        return "graphql"
    log = doc.get("log")
    if isinstance(log, dict) and "entries" in log:
        return "har"
    info = doc.get("info")
    if isinstance(doc.get("item"), list) and isinstance(info, dict):
        return "postman"
    return "unknown"


def load_endpoints(content: str | dict, base_url: str, *, kind: str = "auto") -> list[Endpoint]:
    """Parse any supported spec artifact into endpoints.

    ``content`` may be a raw JSON string or an already-parsed dict. ``kind`` is
    one of openapi3/swagger2/graphql/har/postman, or ``auto`` to sniff it.
    """
    doc: Any
    if isinstance(content, str):
        try:
            doc = json.loads(content)
        except ValueError:
            return []
    else:
        doc = content

    fmt = detect_format(doc) if kind == "auto" else kind
    if fmt in ("openapi3", "swagger2"):
        return parse_openapi(doc, base_url)
    if fmt == "graphql":
        return parse_graphql_introspection(doc, base_url)
    if fmt == "har":
        return parse_har(doc)
    if fmt == "postman":
        return parse_postman(doc)
    return []


# --------------------------------------------------------------------------- #
# Shared schema helpers                                                        #
# --------------------------------------------------------------------------- #
def _deref(node: Any, root: dict, _depth: int = 0) -> Any:
    """Resolve a local ``$ref`` (``#/a/b/c``) against the spec root."""
    if not isinstance(node, dict) or "$ref" not in node or _depth >= _MAX_REF_DEPTH:
        return node
    ref = node["$ref"]
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return node
    target: Any = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")  # JSON-pointer unescape
        if isinstance(target, dict) and part in target:
            target = target[part]
        else:
            return {}
    return _deref(target, root, _depth + 1)


def _sample(schema: Any) -> str:
    """A concrete, type-appropriate placeholder value for a property schema."""
    if not isinstance(schema, dict):
        return "test"
    for key in ("example", "default"):
        if key in schema and schema[key] is not None:
            val = schema[key]
            return val if isinstance(val, str) else json.dumps(val)
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return str(enum[0])
    t = schema.get("type")
    if t in ("integer", "number"):
        return "1"
    if t == "boolean":
        return "true"
    if t == "array":
        return "1"
    return "test"


def _schema_properties(schema: Any, root: dict, _depth: int = 0) -> dict[str, Any]:
    """Top-level property name -> property schema, resolving $ref/allOf."""
    schema = _deref(schema, root, _depth)
    if not isinstance(schema, dict) or _depth >= _MAX_REF_DEPTH:
        return {}
    props = schema.get("properties")
    if isinstance(props, dict):
        return props
    merged: dict[str, Any] = {}
    for combinator in ("allOf", "oneOf", "anyOf"):
        for sub in schema.get(combinator, []) or []:
            merged.update(_schema_properties(sub, root, _depth + 1))
    return merged


# --------------------------------------------------------------------------- #
# OpenAPI 3.x / Swagger 2.0                                                    #
# --------------------------------------------------------------------------- #
def _resolve_server_url(server_url: str, base_url: str) -> str:
    """Turn an OpenAPI ``servers[].url`` into an absolute origin+prefix."""
    base = urlsplit(base_url)
    origin = f"{base.scheme or 'http'}://{base.netloc}"
    if not server_url:
        return origin
    if "://" in server_url:
        return server_url.rstrip("/")
    if server_url.startswith("/"):
        return f"{origin}{server_url}".rstrip("/")
    return f"{origin}/{server_url}".rstrip("/")


def _openapi_base(spec: dict, base_url: str) -> str:
    """The absolute URL prefix that paths hang off, for v3 and v2."""
    if "openapi" in spec:
        servers = spec.get("servers") or []
        server_url = ""
        if servers and isinstance(servers[0], dict):
            server_url = str(servers[0].get("url", ""))
            variables = servers[0].get("variables")
            if isinstance(variables, dict):
                for name, var in variables.items():
                    if isinstance(var, dict) and "default" in var:
                        server_url = server_url.replace(f"{{{name}}}", str(var["default"]))
        return _resolve_server_url(server_url, base_url)

    # Swagger 2.0: host + basePath + schemes
    base = urlsplit(base_url)
    schemes = spec.get("schemes") or [base.scheme or "https"]
    scheme = schemes[0] if isinstance(schemes, list) and schemes else "https"
    host = spec.get("host") or base.netloc
    base_path = str(spec.get("basePath") or "")
    return f"{scheme}://{host}{base_path}".rstrip("/")


def _build_url(base: str, path: str, path_params: dict[str, str], query: dict[str, str]) -> str:
    """Concatenate base+path, substitute {path} params, append query samples."""
    full = f"{base}{path}"
    for name, value in path_params.items():
        full = full.replace(f"{{{name}}}", value or "1")
    # Concretize any undeclared {placeholder} so the URL is actually requestable.
    full = re.sub(r"\{[^/}]+\}", "1", full)
    if not query:
        return full
    parts = urlsplit(full)
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path or "/", urlencode(query, doseq=True), "")
    )


def _param_schema_sample(param: dict, root: dict) -> str:
    """Sample value for an OpenAPI parameter object (v3 nests under 'schema')."""
    if "example" in param and param["example"] is not None:
        ex = param["example"]
        return ex if isinstance(ex, str) else json.dumps(ex)
    if "schema" in param:  # OpenAPI 3
        return _sample(_deref(param["schema"], root))
    return _sample(param)  # Swagger 2 puts type fields on the param itself


def _collect_parameters(
    raw_params: list, root: dict
) -> tuple[list[Param], dict[str, str], dict[str, str]]:
    """Split an OpenAPI/Swagger ``parameters`` list into typed Params.

    Returns (params, path_param_samples, query_param_samples). ``body`` params
    (Swagger 2) are expanded into JSON params from their schema.
    """
    params: list[Param] = []
    path_samples: dict[str, str] = {}
    query_samples: dict[str, str] = {}
    for raw in raw_params:
        raw = _deref(raw, root)
        if not isinstance(raw, dict):
            continue
        loc_in = raw.get("in")
        name = raw.get("name")
        if loc_in == "body":  # Swagger 2.0 JSON body
            for pname, pschema in _schema_properties(raw.get("schema"), root).items():
                params.append(
                    Param(name=str(pname), location=ParamLocation.JSON, value=_sample(pschema))
                )
            continue
        if not name or loc_in not in _IN_TO_LOCATION:
            continue
        location = _IN_TO_LOCATION[loc_in]
        sample = _param_schema_sample(raw, root)
        params.append(Param(name=str(name), location=location, value=sample))
        if location == ParamLocation.PATH:
            path_samples[str(name)] = sample
        elif location == ParamLocation.QUERY:
            query_samples[str(name)] = sample
    return params, path_samples, query_samples


def _request_body_params(operation: dict, root: dict) -> list[Param]:
    """OpenAPI 3 ``requestBody`` -> JSON or form-urlencoded Params."""
    body = _deref(operation.get("requestBody"), root)
    if not isinstance(body, dict):
        return []
    content = body.get("content")
    if not isinstance(content, dict):
        return []
    params: list[Param] = []
    for media_type, media in content.items():
        if not isinstance(media, dict):
            continue
        schema = media.get("schema")
        if "json" in media_type:
            for name, pschema in _schema_properties(schema, root).items():
                params.append(
                    Param(name=str(name), location=ParamLocation.JSON, value=_sample(pschema))
                )
        elif "x-www-form-urlencoded" in media_type or "form-data" in media_type:
            for name, pschema in _schema_properties(schema, root).items():
                params.append(
                    Param(name=str(name), location=ParamLocation.BODY, value=_sample(pschema))
                )
    return params


def parse_openapi(spec: dict, base_url: str) -> list[Endpoint]:
    """OpenAPI 3.x / Swagger 2.0 document -> Endpoints with typed params."""
    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    base = _openapi_base(spec, base_url)
    is_v3 = "openapi" in spec

    endpoints: list[Endpoint] = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared_params = item.get("parameters", []) or []  # path-level params apply to all verbs
        for method_name in _OPENAPI_METHODS:
            operation = item.get(method_name)
            if not isinstance(operation, dict):
                continue
            try:
                method = HttpMethod(method_name.upper())
            except ValueError:
                continue

            raw_params = list(shared_params) + list(operation.get("parameters", []) or [])
            params, path_samples, query_samples = _collect_parameters(raw_params, spec)
            if is_v3:
                params.extend(_request_body_params(operation, spec))

            url = _build_url(base, str(path), path_samples, query_samples)
            endpoints.append(
                Endpoint(
                    url=url,
                    method=method,
                    params=params,
                    content_type="application/json",
                    source="api-spec",
                )
            )
    return endpoints


# --------------------------------------------------------------------------- #
# GraphQL introspection                                                        #
# --------------------------------------------------------------------------- #
def parse_graphql_introspection(doc: dict, url: str) -> list[Endpoint]:
    """GraphQL introspection result -> one POST Endpoint per root field.

    Each query/mutation root field becomes a POST to the GraphQL endpoint with a
    JSON ``query`` param holding a minimal operation document. The query/mutation
    field names are recorded so the GraphQL scanner can target real operations
    rather than guessing.
    """
    schema = doc.get("data", doc)
    schema = schema.get("__schema") if isinstance(schema, dict) else None
    if not isinstance(schema, dict):
        return []

    types = {t.get("name"): t for t in schema.get("types", []) if isinstance(t, dict)}
    endpoints: list[Endpoint] = []
    roots = [
        ("query", schema.get("queryType")),
        ("mutation", schema.get("mutationType")),
    ]
    for op_kind, root_ref in roots:
        if not isinstance(root_ref, dict):
            continue
        root_type = types.get(root_ref.get("name"))
        if not isinstance(root_type, dict):
            continue
        for field in root_type.get("fields", []) or []:
            if not isinstance(field, dict) or not field.get("name"):
                continue
            fname = field["name"]
            arg_names = [a.get("name") for a in field.get("args", []) or [] if a.get("name")]
            arg_stub = f"({', '.join(f'{a}: null' for a in arg_names)})" if arg_names else ""
            query_doc = f"{op_kind} {{ {fname}{arg_stub} }}"
            endpoints.append(
                Endpoint(
                    url=url,
                    method=HttpMethod.POST,
                    params=[Param(name="query", location=ParamLocation.JSON, value=query_doc)],
                    content_type="application/json",
                    source="graphql-introspection",
                )
            )
    return endpoints


# --------------------------------------------------------------------------- #
# HAR (HTTP Archive)                                                           #
# --------------------------------------------------------------------------- #
def parse_har(har: dict) -> list[Endpoint]:
    """HAR log -> Endpoints, reusing the browser-capture conversion."""
    log = har.get("log") if isinstance(har, dict) else None
    if not isinstance(log, dict):
        return []
    endpoints: list[Endpoint] = []
    seen: set[tuple[str, str]] = set()
    for entry in log.get("entries", []) or []:
        if not isinstance(entry, dict):
            continue
        request = entry.get("request")
        if not isinstance(request, dict):
            continue
        method = str(request.get("method", "GET"))
        url = str(request.get("url", ""))
        if not url:
            continue
        post = request.get("postData") if isinstance(request.get("postData"), dict) else {}
        post_data = post.get("text") if isinstance(post, dict) else None
        content_type = post.get("mimeType") if isinstance(post, dict) else None
        # urlencoded HAR bodies sometimes only populate params[], not text.
        if not post_data and isinstance(post.get("params"), list):
            post_data = urlencode(
                {p.get("name"): p.get("value", "") for p in post["params"] if p.get("name")}
            )
        ep = endpoint_from_capture(
            CapturedRequest(
                method=method,
                url=url,
                post_data=post_data,
                content_type=content_type,
                resource_type="xhr",
            )
        )
        if ep is None:
            continue
        ep.source = "har"
        key = (ep.method.value, ep.url)
        if key in seen:
            continue
        seen.add(key)
        endpoints.append(ep)
    return endpoints


# --------------------------------------------------------------------------- #
# Postman collection (v2.x)                                                    #
# --------------------------------------------------------------------------- #
def _postman_url(url_field: Any) -> str:
    """Postman URL is either a raw string or an object with host/path/query."""
    if isinstance(url_field, str):
        return url_field
    if not isinstance(url_field, dict):
        return ""
    raw = url_field.get("raw")
    if isinstance(raw, str) and raw:
        return raw
    protocol = url_field.get("protocol") or "https"
    host = url_field.get("host")
    host_str = ".".join(host) if isinstance(host, list) else str(host or "")
    path = url_field.get("path")
    path_str = "/".join(str(p) for p in path) if isinstance(path, list) else str(path or "")
    url = f"{protocol}://{host_str}/{path_str}"
    query = url_field.get("query")
    if isinstance(query, list):
        pairs = {q.get("key"): q.get("value", "") for q in query if isinstance(q, dict) and q.get("key")}
        if pairs:
            url = f"{url}?{urlencode(pairs)}"
    return url


def _postman_body(body: Any) -> tuple[str | None, str | None]:
    """Return (post_data, content_type) for a Postman request body block."""
    if not isinstance(body, dict):
        return None, None
    mode = body.get("mode")
    if mode == "raw":
        raw = body.get("raw")
        lang = ((body.get("options") or {}).get("raw") or {}).get("language")
        ctype = "application/json" if lang == "json" else None
        return (raw if isinstance(raw, str) else None), ctype
    if mode == "urlencoded":
        pairs = {
            p.get("key"): p.get("value", "")
            for p in body.get("urlencoded", []) or []
            if isinstance(p, dict) and p.get("key")
        }
        return urlencode(pairs), "application/x-www-form-urlencoded"
    if mode == "formdata":
        pairs = {
            p.get("key"): p.get("value", "")
            for p in body.get("formdata", []) or []
            if isinstance(p, dict) and p.get("key")
        }
        return urlencode(pairs), "application/x-www-form-urlencoded"
    return None, None


def parse_postman(collection: dict) -> list[Endpoint]:
    """Postman collection (v2.x) -> Endpoints, recursing nested folders."""
    endpoints: list[Endpoint] = []
    seen: set[tuple[str, str]] = set()

    def walk(items: list) -> None:
        for node in items:
            if not isinstance(node, dict):
                continue
            if isinstance(node.get("item"), list):  # folder
                walk(node["item"])
                continue
            request = node.get("request")
            if not isinstance(request, dict):
                continue
            method = str(request.get("method", "GET"))
            url = _postman_url(request.get("url"))
            if not url:
                continue
            post_data, content_type = _postman_body(request.get("body"))
            ep = endpoint_from_capture(
                CapturedRequest(
                    method=method,
                    url=url,
                    post_data=post_data,
                    content_type=content_type,
                    resource_type="xhr",
                )
            )
            if ep is None:
                continue
            ep.source = "postman"
            key = (ep.method.value, ep.url)
            if key in seen:
                continue
            seen.add(key)
            endpoints.append(ep)

    if isinstance(collection.get("item"), list):
        walk(collection["item"])
    return endpoints


__all__ = [
    "detect_format",
    "load_endpoints",
    "parse_openapi",
    "parse_graphql_introspection",
    "parse_har",
    "parse_postman",
]
