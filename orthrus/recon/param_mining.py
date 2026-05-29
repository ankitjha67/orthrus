"""Parameter-mining recon (Arjun-style hidden-parameter discovery).

Crawling only finds parameters that appear in links/forms. Many endpoints accept
*undeclared* parameters (debug, admin, role, callback, redirect, …) that gate
extra behaviour or new injection sinks. This module probes each discovered GET
endpoint with a wordlist of likely parameter names and, for any whose unique
sentinel value is reflected in the response, emits a new Endpoint carrying that
parameter — expanding the surface every downstream scanner then tests.

A baseline request with a random parameter is sent first; endpoints that reflect
*any* input are skipped (their reflection tells us nothing about a real param).
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Endpoint, HttpMethod, Param, ParamLocation
from orthrus.recon.base import BaseRecon, ReconResult
from orthrus.utils.encoding import with_query_param
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("recon.param-miner")

MAX_ENDPOINTS = 20
MAX_REQUESTS = 900
MAX_FOUND_PER_ENDPOINT = 10

# Common undeclared parameters worth probing for.
CANDIDATE_PARAMS: tuple[str, ...] = (
    "debug", "test", "admin", "id", "uid", "user", "username", "role", "page",
    "per_page", "limit", "offset", "sort", "order", "callback", "jsonp", "redirect",
    "url", "next", "return_url", "format", "lang", "locale", "view", "mode",
    "action", "type", "file", "path", "include", "template", "key", "token",
    "api_key", "fields", "expand", "show", "filter", "preview", "draft", "verbose",
)


def reflected(value: str, body: str) -> bool:
    return value in body


class ParameterMiner(BaseRecon):
    name = "param-miner"

    async def discover(self, ctx: ScanContext) -> AsyncIterator[ReconResult]:
        requests = 0
        endpoints = 0
        for ep in list(ctx.endpoints):
            if ep.method != HttpMethod.GET:
                continue  # query-string mining only (v1)
            if endpoints >= MAX_ENDPOINTS or requests >= MAX_REQUESTS:
                break
            endpoints += 1
            existing = {p.name.lower() for p in ep.params}
            nonce = secrets.token_hex(3)

            # Baseline: a random param. If its value is reflected, the endpoint
            # echoes arbitrary input and mining can't distinguish a real param.
            ctl_value = f"orthrusbase{nonce}"
            ctl_url = with_query_param(ep.url, f"orthrusctl{nonce}", ctl_value)
            if not ctx.scope.is_allowed(ctl_url):
                continue
            ctl = await self._get(ctx, ctl_url)
            if ctl is None:
                continue
            requests += 1
            if reflected(ctl_value, ctl.text):
                continue

            found = 0
            for idx, cand in enumerate(CANDIDATE_PARAMS):
                if cand.lower() in existing:
                    continue
                if requests >= MAX_REQUESTS or found >= MAX_FOUND_PER_ENDPOINT:
                    break
                value = f"orthruspm{nonce}{idx}"
                probe_url = with_query_param(ep.url, cand, value)
                if not ctx.scope.is_allowed(probe_url):
                    continue
                resp = await self._get(ctx, probe_url)
                if resp is None:
                    continue
                requests += 1
                if reflected(value, resp.text):
                    found += 1
                    logger.info("param-miner: discovered hidden param '%s' on %s", cand, ep.url)
                    yield Endpoint(
                        url=with_query_param(ep.url, cand, "1"),
                        method=HttpMethod.GET,
                        params=[Param(name=cand, location=ParamLocation.QUERY, value="1")],
                    )

    async def _get(self, ctx: ScanContext, url: str) -> httpx.Response | None:
        try:
            return await ctx.http.get(url, follow_redirects=False)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("param-miner probe failed for %s: %s", url, exc)
            return None


__all__ = ["ParameterMiner", "reflected", "CANDIDATE_PARAMS"]
