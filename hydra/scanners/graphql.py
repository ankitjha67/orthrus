"""GraphQL scanner (PRD §6.8 GraphQL).

Locates GraphQL endpoints (common paths + crawled hits) and sends an
introspection query. An endpoint that returns its schema has introspection
enabled, which leaks the full API surface. Depth/alias DoS testing is deferred.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from hydra.core.context import ScanContext
from hydra.core.schemas import Confidence, Evidence, Finding, Severity
from hydra.scanners.base_scanner import BaseScanner
from hydra.scanners.registry import register
from hydra.utils.logger import get_logger
from hydra.utils.scope import ScopeViolation

logger = get_logger("scanner.graphql")

SCANNER_NAME = "graphql"

COMMON_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/graphql/console",
    "/graphiql",
    "/query",
    "/api/graphql/v1",
]

INTROSPECTION_QUERY = {"query": "query{__schema{queryType{name} types{name}}}"}


def introspection_enabled(body: str) -> bool:
    return '"__schema"' in body or '"queryType"' in body


def is_graphql_response(body: str) -> bool:
    markers = ("Cannot query field", "Must provide query", "GraphQL", '"errors"')
    return any(m in body for m in markers)


@register
class GraphqlScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "graphql"

    def _candidates(self, ctx: ScanContext) -> list[str]:
        base = urlsplit(ctx.config.target)
        root = f"{base.scheme}://{base.netloc}"
        urls = [root + path for path in COMMON_PATHS]
        urls += [ep.url for ep in ctx.endpoints if "graphql" in urlsplit(ep.url).path.lower()]
        seen: set[str] = set()
        unique: list[str] = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                unique.append(url)
        return unique

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        for url in self._candidates(ctx):
            if not ctx.scope.is_allowed(url):
                continue
            try:
                resp = await ctx.http.post(url, json=INTROSPECTION_QUERY, follow_redirects=False)
            except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
                logger.debug("graphql probe failed for %s: %s", url, exc)
                continue

            body = resp.text
            if introspection_enabled(body):
                yield Finding(
                    vuln_type="graphql",
                    title="GraphQL introspection enabled",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    url=url,
                    description=(
                        "The GraphQL endpoint answered an introspection query, exposing its full "
                        "schema (types, queries, mutations). This aids attackers in mapping the API."
                    ),
                    remediation=(
                        "Disable introspection in production and restrict GraphQL debugging "
                        "interfaces (GraphiQL/Playground)."
                    ),
                    cwe="CWE-200",
                    scanner=SCANNER_NAME,
                    evidence=Evidence(
                        request_raw=str(INTROSPECTION_QUERY),
                        matched_at="__schema",
                    ),
                )
            elif is_graphql_response(body):
                yield Finding(
                    vuln_type="graphql",
                    title="GraphQL endpoint detected (introspection disabled)",
                    severity=Severity.INFO,
                    confidence=Confidence.FIRM,
                    url=url,
                    description="A GraphQL endpoint was found; introspection appears disabled.",
                    remediation="Ensure the endpoint enforces auth, depth limits, and rate limiting.",
                    cwe="CWE-200",
                    scanner=SCANNER_NAME,
                    evidence=Evidence(notes="GraphQL error/response markers present"),
                )


__all__ = ["GraphqlScanner", "introspection_enabled", "is_graphql_response"]
