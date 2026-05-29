"""Passive technology fingerprinting (PRD §5.3).

Identifies server software, backend frameworks, CMS, and JS libraries from
response headers, cookies, and body signatures. Passive only: it inspects
responses ORTHRUS already had to make; it sends no probing payloads here.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from orthrus.core import schemas
from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Technology
from orthrus.recon.base import BaseRecon
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("recon.fingerprint")

# Set-Cookie name -> (technology, category)
_COOKIE_SIGNATURES = {
    "phpsessid": ("PHP", "language"),
    "jsessionid": ("Java", "language"),
    "asp.net_sessionid": ("ASP.NET", "framework"),
    "aspsessionid": ("ASP", "framework"),
    "laravel_session": ("Laravel", "framework"),
    "ci_session": ("CodeIgniter", "framework"),
    "django": ("Django", "framework"),
    "csrftoken": ("Django", "framework"),
    "_rails": ("Ruby on Rails", "framework"),
    "express": ("Express", "framework"),
    "connect.sid": ("Express", "framework"),
}

# Response header -> (technology, category); value is appended as version when present.
_HEADER_SIGNATURES = {
    "server": ("server", None),
    "x-powered-by": ("framework", None),
    "x-aspnet-version": ("ASP.NET", "framework"),
    "x-aspnetmvc-version": ("ASP.NET MVC", "framework"),
    "x-drupal-cache": ("Drupal", "cms"),
    "x-generator": ("generator", None),
}

# Body regex -> (technology, category)
_BODY_SIGNATURES: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"/wp-(content|includes)/", re.I), "WordPress", "cms"),
    (re.compile(r'name=["\']generator["\']\s+content=["\']WordPress', re.I), "WordPress", "cms"),
    (re.compile(r'name=["\']generator["\']\s+content=["\']Drupal', re.I), "Drupal", "cms"),
    (re.compile(r'name=["\']generator["\']\s+content=["\']Joomla', re.I), "Joomla", "cms"),
    (re.compile(r"Shopify\.theme", re.I), "Shopify", "cms"),
    (re.compile(r"\breact(?:-dom)?(?:\.production)?\.min\.js", re.I), "React", "js-library"),
    (re.compile(r"\bvue(?:\.runtime)?(?:\.min)?\.js", re.I), "Vue", "js-library"),
    (re.compile(r"\bangular(?:\.min)?\.js", re.I), "Angular", "js-library"),
    (re.compile(r"\bjquery[-.]?\d", re.I), "jQuery", "js-library"),
]

_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I
)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def _split_product_version(value: str) -> tuple[str, str | None]:
    match = re.match(r"^([^/\s]+)[/ ]?([0-9][\w.\-]*)?", value.strip())
    if not match:
        return value.strip(), None
    return match.group(1), match.group(2)


def identify(
    headers: dict[str, str],
    body: str,
    set_cookie_names: list[str],
) -> list[Technology]:
    """Return technologies inferred from a single response."""
    found: dict[str, Technology] = {}

    def add(name: str, version: str | None, category: str | None, conf: Confidence) -> None:
        existing = found.get(name)
        if existing is None:
            found[name] = Technology(
                name=name, version=version, category=category, confidence=conf
            )
        elif version and not existing.version:
            existing.version = version

    lower_headers = {k.lower(): v for k, v in headers.items()}

    for header, (tech, category) in _HEADER_SIGNATURES.items():
        if header not in lower_headers:
            continue
        value = lower_headers[header]
        if category is None:
            product, version = _split_product_version(value)
            cat = "server" if header == "server" else "framework"
            add(product, version, cat, Confidence.FIRM)
        else:
            add(tech, None, category, Confidence.FIRM)

    for raw_name in set_cookie_names:
        name = raw_name.split("=", 1)[0].strip().lower()
        for sig, (tech, category) in _COOKIE_SIGNATURES.items():
            if sig in name:
                add(tech, None, category, Confidence.FIRM)

    gen = _GENERATOR_RE.search(body)
    if gen:
        product, version = _split_product_version(gen.group(1))
        add(product, version, "cms", Confidence.FIRM)

    for pattern, tech, category in _BODY_SIGNATURES:
        if pattern.search(body):
            add(tech, None, category, Confidence.TENTATIVE)

    return list(found.values())


def extract_title(body: str) -> str | None:
    match = _TITLE_RE.search(body)
    if not match:
        return None
    return re.sub(r"\s+", " ", match.group(1)).strip() or None


class TechFingerprint(BaseRecon):
    """Probes the target's web root over http/https and yields an enriched Asset."""

    name = "tech-fingerprint"

    async def discover(self, ctx: ScanContext) -> AsyncIterator[schemas.Asset]:
        target = ctx.config.target
        parts = urlsplit(target if "://" in target else f"//{target}")
        host = (parts.hostname or target).lower()
        netloc = parts.netloc or host

        # Honor the target's scheme + explicit port. Only probe the alternate
        # scheme when no explicit port was given (default 80/443).
        if parts.scheme:
            schemes = [parts.scheme]
            if parts.port is None:
                schemes.append("http" if parts.scheme == "https" else "https")
        else:
            schemes = ["https", "http"]

        asset = schemas.Asset(fqdn=host, discovery_method="fingerprint")

        for scheme in schemes:
            url = f"{scheme}://{netloc}/"
            if not ctx.scope.is_allowed(url):
                continue
            try:
                resp = await ctx.http.get(url)
            except ScopeViolation:
                continue
            except httpx.HTTPError as exc:
                logger.debug("fingerprint fetch failed for %s: %s", url, exc)
                continue

            if scheme == "https":
                asset.https_available = True
            else:
                asset.http_available = True
            asset.status_code = resp.status_code

            body = resp.text if "text" in resp.headers.get("content-type", "") else ""
            set_cookies = resp.headers.get_list("set-cookie")
            techs = identify(dict(resp.headers), body, set_cookies)
            _merge_technologies(asset, techs)
            if not asset.title:
                asset.title = extract_title(body)

        yield asset


def _merge_technologies(asset: schemas.Asset, techs: list[Technology]) -> None:
    existing = {t.name for t in asset.technologies}
    for tech in techs:
        if tech.name not in existing:
            asset.technologies.append(tech)
            existing.add(tech.name)


__all__ = ["TechFingerprint", "identify", "extract_title"]
