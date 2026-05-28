"""Shared injection plumbing for parameter-probing scanners.

Centralizes request building across the injectable parameter locations
(query string, form-urlencoded body, and JSON body) and HTTP methods so each
scanner only supplies payloads and a detector. Every request still flows
through the scope-enforced HttpClient.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from hydra.core.context import ScanContext
from hydra.core.schemas import Endpoint, HttpMethod, ParamLocation
from hydra.utils.encoding import with_query_param
from hydra.utils.scope import ScopeViolation

# Locations this module knows how to mutate and send.
INJECTABLE_LOCATIONS = (ParamLocation.QUERY, ParamLocation.BODY, ParamLocation.JSON)
# Methods that carry a request body (so BODY/JSON params are reachable).
BODY_METHODS = (HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE)


@dataclass
class InjectionPoint:
    endpoint: Endpoint
    param: str
    location: ParamLocation
    method: HttpMethod

    @property
    def base_url(self) -> str:
        return self.endpoint.url


def injection_points(ctx: ScanContext) -> Iterator[InjectionPoint]:
    """Yield unique (method, path, location, param) injection points.

    Query params are reachable on any method; form-body and JSON params are
    only reachable on body-bearing methods (POST/PUT/PATCH/DELETE).
    """
    seen: set[tuple[str, str, str, str]] = set()
    for endpoint in ctx.endpoints:
        path = urlsplit(endpoint.url).path
        for param in endpoint.params:
            loc = param.location
            if loc not in INJECTABLE_LOCATIONS:
                continue
            if loc in (ParamLocation.BODY, ParamLocation.JSON) and endpoint.method not in BODY_METHODS:
                continue
            key = (endpoint.method.value, path, loc.value, param.name)
            if key in seen:
                continue
            seen.add(key)
            yield InjectionPoint(endpoint, param.name, loc, endpoint.method)


def _body_with(endpoint: Endpoint, target: str, value: str, location: ParamLocation) -> dict:
    """Rebuild the request body for ``location``, placing ``value`` in ``target``."""
    return {
        p.name: (value if p.name == target else (p.value or "1"))
        for p in endpoint.params
        if p.location == location
    }


def used_url(point: InjectionPoint, value: str) -> str:
    """The URL a probe targets (query-mutated for query params, base otherwise)."""
    if point.location == ParamLocation.QUERY:
        return with_query_param(point.endpoint.url, point.param, value)
    return point.endpoint.url


async def send(
    ctx: ScanContext,
    point: InjectionPoint,
    value: str,
    *,
    follow_redirects: bool = True,
) -> httpx.Response | None:
    """Send a probe placing ``value`` in ``point``'s parameter. None on failure.

    Dispatches on the parameter location: query → mutated URL, JSON → JSON body,
    form body → urlencoded body. Uses the endpoint's own HTTP method.
    """
    ep = point.endpoint
    method = ep.method.value
    try:
        if point.location == ParamLocation.QUERY:
            url = with_query_param(ep.url, point.param, value)
            return await ctx.http.request(method, url, follow_redirects=follow_redirects)
        if point.location == ParamLocation.JSON:
            body = _body_with(ep, point.param, value, ParamLocation.JSON)
            return await ctx.http.request(method, ep.url, json=body, follow_redirects=follow_redirects)
        # form-urlencoded body
        data = _body_with(ep, point.param, value, ParamLocation.BODY)
        return await ctx.http.request(method, ep.url, data=data, follow_redirects=follow_redirects)
    except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL):
        return None


__all__ = [
    "InjectionPoint",
    "injection_points",
    "send",
    "used_url",
    "INJECTABLE_LOCATIONS",
    "BODY_METHODS",
]
