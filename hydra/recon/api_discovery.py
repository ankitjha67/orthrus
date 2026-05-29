"""API discovery (PRD §5.2 / api_discovery).

Two complementary jobs:

1. **Probe** common API-descriptor paths (OpenAPI/Swagger) and the GraphQL root,
   surfacing REST/GraphQL roots and flagging machine-readable specs.
2. **Import** any spec it finds (or one the operator supplies via
   ``config.import_spec``) into concrete endpoints with typed params — turning a
   Swagger/OpenAPI/GraphQL/HAR/Postman contract into the actual JSON/REST attack
   surface for the scan phase.

Every request still flows through the scope-enforced HttpClient, and imported
endpoints are filtered to in-scope URLs. Pure parsing lives in ``spec_parsers``.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from hydra.core import schemas
from hydra.core.context import ScanContext
from hydra.core.schemas import Endpoint, HttpMethod
from hydra.recon.base import BaseRecon
from hydra.recon.spec_parsers import load_endpoints, parse_graphql_introspection
from hydra.utils.logger import get_logger
from hydra.utils.scope import ScopeViolation

logger = get_logger("recon.api")

SPEC_PATHS = [
    "/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/v2/api-docs",
    "/v3/api-docs", "/api-docs", "/api/swagger.json", "/api/openapi.json",
    "/.well-known/openapi.json", "/api", "/api/v1", "/api/v2", "/graphql",
]

# Minimal introspection query — asks only for the operation root field names.
_INTROSPECTION_QUERY = (
    "query{__schema{queryType{name}mutationType{name}"
    "types{name fields{name args{name}}}}}"
)


def looks_like_api_spec(body: str) -> bool:
    snippet = body[:4000].lower()
    return ('"openapi"' in snippet or '"swagger"' in snippet) and '"paths"' in snippet


def _read_local_spec(location: str) -> str | None:
    """Read a spec file from disk (offloaded to a thread by the caller)."""
    path = Path(location)
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace")


class ApiDiscovery(BaseRecon):
    name = "api-discovery"

    async def discover(self, ctx: ScanContext) -> AsyncIterator[schemas.Endpoint]:
        parts = urlsplit(ctx.config.target if "://" in ctx.config.target else f"//{ctx.config.target}")
        root = f"{parts.scheme or 'http'}://{parts.netloc or parts.path}"

        emitted: set[tuple[str, str]] = set()

        # 1. Operator-supplied spec (local file or in-scope URL) takes priority.
        if ctx.config.import_spec:
            async for ep in self._import_explicit(ctx, ctx.config.import_spec, root):
                if (key := (ep.method.value, ep.url)) not in emitted:
                    emitted.add(key)
                    yield ep

        # 2. Probe well-known descriptor paths; import any real spec found.
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

            yield Endpoint(
                url=url,
                method=HttpMethod.GET,
                response_status=resp.status_code,
                content_type=resp.headers.get("content-type"),
                source="api-discovery",
            )

            if path == "/graphql":
                async for ep in self._introspect_graphql(ctx, url):
                    if (key := (ep.method.value, ep.url)) not in emitted:
                        emitted.add(key)
                        yield ep
            elif looks_like_api_spec(body):
                logger.info("API specification found: %s", url)
                for ep in self._import_text(body, url, ctx):
                    if (key := (ep.method.value, ep.url)) not in emitted:
                        emitted.add(key)
                        yield ep

    # ---------------------------------------------------------------- helpers
    async def _import_explicit(
        self, ctx: ScanContext, location: str, root: str
    ) -> AsyncIterator[Endpoint]:
        """Load an operator-supplied spec from a local file or in-scope URL."""
        content: str | None = None
        base_url = root
        if "://" in location:
            if not ctx.scope.is_allowed(location):
                logger.warning("import spec %s is out of scope; skipping", location)
                return
            try:
                resp = await ctx.http.get(location)
            except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL):
                logger.warning("could not fetch import spec %s", location)
                return
            content, base_url = resp.text, location
        else:
            content = await asyncio.to_thread(_read_local_spec, location)
            if content is None:
                logger.warning("import spec file not found: %s", location)
                return

        count = 0
        for ep in self._import_text(content, base_url, ctx):
            count += 1
            yield ep
        logger.info("imported %d endpoint(s) from spec %s", count, location)

    async def _introspect_graphql(self, ctx: ScanContext, url: str) -> AsyncIterator[Endpoint]:
        """POST an introspection query and convert the schema into endpoints."""
        try:
            resp = await ctx.http.post(url, json={"query": _INTROSPECTION_QUERY})
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL):
            return
        if resp.status_code != 200:
            return
        try:
            doc = resp.json()
        except (ValueError, json.JSONDecodeError):
            return
        eps = parse_graphql_introspection(doc, url)
        if eps:
            logger.info("GraphQL introspection enabled at %s: %d operation(s)", url, len(eps))
        for ep in eps:
            if ctx.scope.is_allowed(ep.url):
                yield ep

    @staticmethod
    def _import_text(content: str, base_url: str, ctx: ScanContext) -> list[Endpoint]:
        """Parse spec text and keep only in-scope endpoints."""
        return [ep for ep in load_endpoints(content, base_url) if ctx.scope.is_allowed(ep.url)]


__all__ = ["ApiDiscovery", "looks_like_api_spec", "SPEC_PATHS"]
