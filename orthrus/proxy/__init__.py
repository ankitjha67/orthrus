"""Scope-aware HTTP capturing proxy (`orthrus proxy`).

Browse an authorized target through this proxy and the endpoints/parameters it
observes are captured into the endpoint store to seed the scanner. Deny-by-default:
out-of-scope requests are blocked unless explicitly passed through.
"""

from __future__ import annotations

from orthrus.proxy.server import (
    ParsedRequest,
    ProxyServer,
    build_response_head,
    extract_endpoint,
    parse_request_head,
)

__all__ = [
    "ProxyServer",
    "ParsedRequest",
    "parse_request_head",
    "build_response_head",
    "extract_endpoint",
]
