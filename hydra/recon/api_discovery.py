"""API discovery (PRD §5.2 / api_discovery).

Probes common API-descriptor paths (OpenAPI/Swagger) and surfaces REST/GraphQL
API roots, widening the surface and flagging machine-readable specs that map the
whole API. Pure ``looks_like_api_spec`` is unit-tested.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from hydra.core import schemas
from hydra.core.context import ScanContext
from hydra.core.schemas import Endpoint, HttpMethod
from hydra.recon.base import BaseRecon
from hydra.utils.logger import get_logger
from hydra.utils.scope import ScopeViolation

logger = get_logger("recon.api")

SPEC_PATHS = [
    "/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/v2/api-docs",
    "/v3/api-docs", "/api-docs", "/api/swagger.json", "/api/openapi.json",
    "/.well-known/openapi.json", "/api", "/api/v1", "/api/v2", "/graphql",
]


def looks_like_api_spec(body: str) -> bool:
    snippet = body[:4000].lower()
    return ('"openapi"' in snippet or '"swagger"' in snippet) and '"paths"' in snippet


class ApiDiscovery(BaseRecon):
    name = "api-discovery"

    async def discover(self, ctx: ScanContext) -> AsyncIterator[schemas.Endpoint]:
        parts = urlsplit(ctx.config.target if "://" in ctx.config.target else f"//{ctx.config.target}")
        root = f"{parts.scheme or 'http'}://{parts.netloc or parts.path}"

        for path in SPEC_PATHS:
            url = f"{root}{path}"
            if not ctx.scope.is_allowed(url):
                continue
            try:
                resp = await ctx.http.get(url, follow_redirects=False)
            except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL):
                continue
            if resp.status_code not in (200, 401, 403):
                continue
            body = resp.text
            if looks_like_api_spec(body):
                logger.info("API specification found: %s", url)
            yield Endpoint(
                url=url,
                method=HttpMethod.GET,
                response_status=resp.status_code,
                content_type=resp.headers.get("content-type"),
                source="api-discovery",
            )


__all__ = ["ApiDiscovery", "looks_like_api_spec", "SPEC_PATHS"]
