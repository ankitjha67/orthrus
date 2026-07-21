"""Neutral captured-request model + graph-folding for the traffic bridges.

:class:`CapturedRequest` is what every proxy-export parser normalizes to; it is
tool-agnostic so Burp, Caido, HAR, or a future source all fold identically.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from orthrus.model.store import ProgramGraph

# path substrings that make a route worth testing first (auth surface, mutations,
# APIs, file handling). Kept small + high-signal — this only ranks, never filters.
_JUICY_HINTS = (
    "admin", "api", "graphql", "login", "logout", "auth", "token", "oauth", "sso",
    "password", "reset", "account", "user", "profile", "session", "upload", "file",
    "download", "export", "import", "payment", "checkout", "order", "invoice",
    "internal", "debug", "config", "setting", "key", "secret", "webhook", "callback",
)
_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass
class CapturedRequest:
    """One HTTP request/response observed in a proxy history (tool-neutral)."""

    method: str = "GET"
    host: str = ""
    path: str = "/"
    scheme: str = "https"
    port: int | None = None
    query_params: list[str] = field(default_factory=list)
    body_params: list[str] = field(default_factory=list)
    status: int | None = None
    content_type: str | None = None
    response_size: int | None = None

    def normalized_host(self) -> str:
        return (self.host or "").strip().lower().rstrip(".")


@dataclass
class TrafficImportResult:
    """Summary of a fold: what became graph state and what was refused."""

    source: str = "import"
    total: int = 0
    new_assets: int = 0
    seen_assets: int = 0
    new_endpoints: int = 0
    seen_endpoints: int = 0
    skipped_out_of_scope: int = 0
    skipped_no_host: int = 0
    hosts: list[str] = field(default_factory=list)


def _asset_kind(host: str) -> str:
    """An IP literal is an ``ip`` asset; anything else is a ``subdomain``."""
    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        return "subdomain"


def endpoint_juicy_score(req: CapturedRequest) -> float:
    """Heuristic 0..1 — how worth-testing this route is (ranks the endpoint queue).

    Purely advisory triage signal: input vectors + state-changing verbs + auth/API
    surface score higher, so a hand-browsed session bubbles its interesting routes
    to the top of ``list_endpoints`` without any scanning yet.
    """
    score = 0.1
    if req.query_params or req.body_params:
        score += 0.3
    if (req.method or "").upper() in _MUTATING:
        score += 0.2
    low = f"{req.path}".lower()
    if any(h in low for h in _JUICY_HINTS):
        score += 0.25
    if req.content_type and any(t in req.content_type.lower() for t in ("json", "xml", "graphql")):
        score += 0.15
    return round(min(score, 1.0), 3)


async def fold_traffic(
    graph: ProgramGraph,
    program_id: str,
    requests: list[CapturedRequest],
    *,
    source: str = "import",
    in_scope: Callable[[str], bool] | None = None,
) -> TrafficImportResult:
    """Fold captured requests into the graph as assets + endpoints (dedup upsert).

    ``in_scope`` (host -> bool), when given, refuses out-of-scope hosts so a proxy
    history's third-party noise never enters the program graph — deny-by-default
    carried onto import. Returns a :class:`TrafficImportResult` for the caller to
    report and audit-log.
    """
    result = TrafficImportResult(source=source, total=len(requests))
    seen_hosts: dict[str, str] = {}  # host -> asset_id (avoid re-upserting per request)
    hosts_ordered: list[str] = []
    for req in requests:
        host = req.normalized_host()
        if not host:
            result.skipped_no_host += 1
            continue
        if in_scope is not None and not in_scope(host):
            result.skipped_out_of_scope += 1
            continue

        asset_id = seen_hosts.get(host)
        if asset_id is None:
            asset, is_new = await graph.record_asset(
                program_id, _asset_kind(host), host,
                discovered_by=source, metadata={"source": source},
            )
            asset_id = asset.id
            seen_hosts[host] = asset_id
            hosts_ordered.append(host)
            if is_new:
                result.new_assets += 1
            else:
                result.seen_assets += 1

        _ep, ep_new = await graph.record_endpoint(
            asset_id, req.path, method=req.method,
            query_params=req.query_params, body_params=req.body_params,
            response_status=req.status, response_content_type=req.content_type,
            response_size=req.response_size, juicy_score=endpoint_juicy_score(req),
        )
        if ep_new:
            result.new_endpoints += 1
        else:
            result.seen_endpoints += 1

    result.hosts = hosts_ordered
    return result


__all__ = [
    "CapturedRequest",
    "TrafficImportResult",
    "endpoint_juicy_score",
    "fold_traffic",
]
