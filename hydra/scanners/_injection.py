"""Shared injection plumbing for parameter-probing scanners.

Centralizes the GET-query vs POST-body request building so each scanner only
has to supply payloads and a detector. Every request still flows through the
scope-enforced HttpClient.
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
    """Yield unique (method, path, param) injection points from the inventory."""
    seen: set[tuple[str, str, str]] = set()
    for endpoint in ctx.endpoints:
        if endpoint.method == HttpMethod.GET:
            wanted = ParamLocation.QUERY
        elif endpoint.method == HttpMethod.POST:
            wanted = ParamLocation.BODY
        else:
            continue
        path = urlsplit(endpoint.url).path
        for param in endpoint.params:
            if param.location != wanted:
                continue
            key = (endpoint.method.value, path, param.name)
            if key in seen:
                continue
            seen.add(key)
            yield InjectionPoint(endpoint, param.name, wanted, endpoint.method)


def used_url(point: InjectionPoint, value: str) -> str:
    """The URL a probe targets (query-mutated for GET, base for POST)."""
    if point.method == HttpMethod.GET:
        return with_query_param(point.endpoint.url, point.param, value)
    return point.endpoint.url


async def send(
    ctx: ScanContext,
    point: InjectionPoint,
    value: str,
    *,
    follow_redirects: bool = True,
) -> httpx.Response | None:
    """Send a probe placing ``value`` in ``point``'s parameter. None on failure."""
    try:
        if point.method == HttpMethod.GET:
            url = with_query_param(point.endpoint.url, point.param, value)
            return await ctx.http.get(url, follow_redirects=follow_redirects)
        data = {
            p.name: (value if p.name == point.param else (p.value or "1"))
            for p in point.endpoint.params
            if p.location == ParamLocation.BODY
        }
        return await ctx.http.post(point.endpoint.url, data=data, follow_redirects=follow_redirects)
    except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL):
        return None


__all__ = ["InjectionPoint", "injection_points", "send", "used_url"]
