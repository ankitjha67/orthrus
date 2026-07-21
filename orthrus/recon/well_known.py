"""`/.well-known/` discovery (RFC 8615 and friends).

Standardized well-known URIs leak a lot of high-value surface for free:

* **openid-configuration** / **oauth-authorization-server** - the JSON advertises
  the identity provider's ``authorization_endpoint``, ``token_endpoint``,
  ``jwks_uri``, ``userinfo_endpoint``, ``registration_endpoint`` … i.e. the whole
  auth attack surface, which the auth/JWT/OAuth scanners then get to test.
* **security.txt** - Contact/Policy URLs (and a disclosure-program hint).
* **change-password**, **assetlinks.json**, **apple-app-site-association**,
  **mta-sts.txt**, **host-meta** - password-management and app-linkage surface.

Everything is fetched through the scope-enforced ``ctx.http`` and every referenced
URL is scope-checked before it's yielded. The pure ``parse_openid_config`` /
``parse_security_txt`` helpers are unit-tested.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Endpoint, HttpMethod
from orthrus.recon.base import BaseRecon
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("recon.well_known")

WELL_KNOWN_PATHS = (
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/change-password",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/.well-known/mta-sts.txt",
    "/.well-known/host-meta",
)
_OIDC_PATHS = ("openid-configuration", "oauth-authorization-server")


def _base_url(target: str) -> str:
    parts = urlsplit(target if "://" in target else f"//{target}")
    scheme = parts.scheme or "http"
    return f"{scheme}://{parts.netloc}"


def parse_openid_config(data: object) -> list[str]:
    """Extract the endpoint/URI URLs advertised by an OIDC/OAuth metadata document."""
    if not isinstance(data, dict):
        return []
    urls: list[str] = []
    for key, value in data.items():
        if not isinstance(value, str) or not value.startswith(("http://", "https://")):
            continue
        if key.endswith("_endpoint") or key.endswith("_uri") or key in ("jwks_uri", "issuer"):
            urls.append(value)
    return list(dict.fromkeys(urls))


def parse_security_txt(text: str) -> list[str]:
    """Extract the URL values from a security.txt (Contact/Policy/Acknowledgments/…)."""
    urls: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        field, sep, value = line.partition(":")
        if not sep:
            continue
        value = (sep + value).lstrip(":").strip()  # keep the rest after the first ':'
        if value.startswith(("http://", "https://")):
            urls.append(value)
    return list(dict.fromkeys(urls))


class WellKnown(BaseRecon):
    name = "well-known"

    async def discover(self, ctx: ScanContext) -> AsyncIterator[Endpoint]:
        base = _base_url(ctx.config.target)
        seen: set[str] = set()
        for path in WELL_KNOWN_PATHS:
            url = f"{base}{path}"
            if not ctx.scope.is_allowed(url):
                continue
            try:
                resp = await ctx.http.get(url, follow_redirects=True)
            except (ScopeViolation, httpx.HTTPError) as exc:
                logger.debug("well-known fetch failed (%s): %s", url, exc)
                continue
            if resp.status_code != 200:
                continue
            if url not in seen:
                seen.add(url)
                yield Endpoint(url=url, method=HttpMethod.GET, source="well-known")

            referenced: list[str] = []
            if path.endswith(_OIDC_PATHS):
                try:
                    referenced = parse_openid_config(resp.json())
                except ValueError:
                    referenced = []
            elif path.endswith("security.txt"):
                referenced = parse_security_txt(resp.text)

            for ref in referenced:
                if ref not in seen and ctx.scope.is_allowed(ref):
                    seen.add(ref)
                    yield Endpoint(url=ref, method=HttpMethod.GET, source="well-known")


__all__ = ["WellKnown", "parse_openid_config", "parse_security_txt", "WELL_KNOWN_PATHS"]
