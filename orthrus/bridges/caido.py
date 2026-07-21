"""Parse a Caido JSON request export into CapturedRequests.

Caido exports proxy/HTTP-history requests as JSON. The exact envelope varies by
Caido version (a bare array, ``{"requests": [...]}``, or a GraphQL-style
``{"data": {"requests": {"edges": [{"node": {...}}]}}}``), and field names differ
(``isTls``/``is_tls``, ``statusCode``/``status_code``). We unwrap the common
shapes and map tolerantly, returning ``[]`` on anything unrecognizable.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs

from orthrus.bridges.base import CapturedRequest


def _first(d: dict, *keys, default=None):
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


def _unwrap(data) -> list[dict]:
    """Reduce Caido's assorted export envelopes to a flat list of request dicts."""
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if not isinstance(data, dict):
        return []
    node = data
    # descend a GraphQL data->requests->edges->node envelope if present
    if isinstance(node.get("data"), dict):
        node = node["data"]
    reqs = _first(node, "requests", "items", "history", "results", default=node.get("requests"))
    if isinstance(reqs, dict) and isinstance(reqs.get("edges"), list):
        return [e["node"] for e in reqs["edges"]
                if isinstance(e, dict) and isinstance(e.get("node"), dict)]
    if isinstance(reqs, list):
        return [r for r in reqs if isinstance(r, dict)]
    return []


def _scheme(req: dict) -> str:
    tls = _first(req, "isTls", "is_tls", "tls", "secure")
    if tls is not None:
        return "https" if tls else "http"
    return str(_first(req, "scheme", "protocol", default="https")).lower() or "https"


def _response_bits(req: dict) -> tuple[int | None, str | None, int | None]:
    resp = req.get("response") if isinstance(req.get("response"), dict) else req
    status = _first(resp, "statusCode", "status_code", "status", "code")
    length = _first(resp, "length", "raw_length", "rawLength", "size", "responseLength")
    ctype = _first(resp, "mimetype", "mimeType", "contentType", "content_type")
    return (
        int(status) if isinstance(status, (int, str)) and str(status).isdigit() else None,
        str(ctype) if ctype else None,
        int(length) if isinstance(length, (int, str)) and str(length).isdigit() else None,
    )


def _body_params(req: dict) -> list[str]:
    body = _first(req, "body", "requestBody", "request_body")
    if isinstance(body, str) and body.strip():
        text = body.strip()
        if text[:1] in "{[":
            try:
                obj = json.loads(text)
                return sorted(obj.keys()) if isinstance(obj, dict) else []
            except ValueError:
                return []
        if "=" in text:
            return sorted({p.split("=", 1)[0] for p in text.split("&") if p.split("=", 1)[0]})
    return []


def parse_caido_json(json_text: str) -> list[CapturedRequest]:
    """Map a Caido JSON export to CapturedRequests (pure; tolerant of garbage)."""
    if not (json_text or "").strip():
        return []
    try:
        data = json.loads(json_text)
    except ValueError:
        return []

    out: list[CapturedRequest] = []
    for req in _unwrap(data):
        host = str(_first(req, "host", "hostname", default="")).strip().lower()
        if not host:
            continue
        query = _first(req, "query", "querystring", "queryString", default="")
        query_params = sorted(parse_qs(query).keys()) if isinstance(query, str) else []
        port = _first(req, "port")
        status, ctype, length = _response_bits(req)
        out.append(
            CapturedRequest(
                method=str(_first(req, "method", "verb", default="GET")).upper(),
                host=host,
                path=str(_first(req, "path", "url_path", default="/")) or "/",
                scheme=_scheme(req),
                port=int(port) if isinstance(port, (int, str)) and str(port).isdigit() else None,
                query_params=query_params,
                body_params=_body_params(req),
                status=status,
                content_type=ctype,
                response_size=length,
            )
        )
    return out


__all__ = ["parse_caido_json"]
