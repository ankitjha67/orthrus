"""Template-driven scanner — runs declarative templates against in-scope hosts.

Loaded only when the operator passes ``--templates`` (a path or ``builtin``), so
it never duplicates the dedicated Python scanners during a default scan. Every
request goes through the scope-enforced ``ctx.http`` like any other module.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from hydra.core.context import ScanContext
from hydra.core.schemas import Confidence, Evidence, Finding
from hydra.scanners.base_scanner import BaseScanner
from hydra.scanners.registry import register
from hydra.templates.loader import load_templates
from hydra.templates.matchers import MatchInput, eval_request_matchers, run_extractors
from hydra.templates.schema import RequestTemplate, Template
from hydra.utils.logger import get_logger
from hydra.utils.scope import ScopeViolation

logger = get_logger("scanner.templates")

SCANNER_NAME = "templates"
MAX_BASE_URLS = 10
MAX_REQUESTS = 1000


def render(value: str, base: str) -> str:
    """Substitute Nuclei-style placeholders against a base URL."""
    parts = urlsplit(base)
    root = f"{parts.scheme}://{parts.netloc}"
    rendered = (
        value.replace("{{BaseURL}}", root)
        .replace("{{RootURL}}", root)
        .replace("{{Hostname}}", parts.netloc)
        .replace("{{Host}}", parts.hostname or "")
    )
    if "{{" not in value and rendered.startswith("/"):
        rendered = root + rendered
    return rendered


def _base_urls(ctx: ScanContext) -> list[str]:
    seen: list[str] = []
    candidates = [ctx.config.target] + [ep.url for ep in ctx.endpoints]
    for url in candidates:
        parts = urlsplit(url if "://" in url else f"http://{url}")
        if not parts.netloc:
            continue
        base = f"{parts.scheme or 'http'}://{parts.netloc}"
        if base not in seen and ctx.scope.is_allowed(base):
            seen.append(base)
        if len(seen) >= MAX_BASE_URLS:
            break
    return seen


@register
class TemplateScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "template"

    def __init__(self) -> None:
        self._templates: list[Template] = []

    def applicable(self, ctx: ScanContext) -> bool:
        return bool(ctx.config.templates)

    async def setup(self, ctx: ScanContext) -> None:
        if not ctx.config.templates:
            return
        try:
            self._templates = load_templates(ctx.config.templates)
        except FileNotFoundError as exc:
            logger.warning("template load failed: %s", exc)
            self._templates = []

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        if not self._templates:
            return
        bases = _base_urls(ctx)
        budget = MAX_REQUESTS
        emitted: set[tuple[str, str]] = set()

        for template in self._templates:
            for base in bases:
                for request in template.requests:
                    if budget <= 0:
                        logger.info("templates: request budget exhausted")
                        return
                    async for finding in self._run_request(
                        ctx, template, request, base, emitted
                    ):
                        yield finding
                    budget -= len(request.path)

    async def _run_request(
        self,
        ctx: ScanContext,
        template: Template,
        request: RequestTemplate,
        base: str,
        emitted: set[tuple[str, str]],
    ) -> AsyncIterator[Finding]:
        for raw_path in request.path:
            url = render(raw_path, base)
            headers = {k: render(v, base) for k, v in request.headers.items()}
            body = render(request.body, base) if request.body else None
            try:
                resp = await ctx.http.request(
                    request.method.upper(),
                    url,
                    headers=headers or None,
                    content=body,
                    follow_redirects=request.redirects,
                )
            except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL):
                continue

            data = MatchInput(
                status=resp.status_code,
                body=resp.text,
                headers="".join(f"{k}: {v}\n" for k, v in resp.headers.items()),
            )
            matched, matched_strings = eval_request_matchers(request, data)
            if not matched:
                continue

            key = (template.id, url)
            if key in emitted:
                continue
            emitted.add(key)

            extracted = run_extractors(request.extractors, data)
            yield self._finding(template, url, matched_strings, extracted, resp.status_code)
            if request.stop_at_first_match:
                return

    def _finding(
        self,
        template: Template,
        url: str,
        matched_strings: list[str],
        extracted: dict[str, str],
        status: int,
    ) -> Finding:
        info = template.info
        notes = f"template={template.id} matched={matched_strings[:5]}"
        if extracted:
            notes += f" extracted={extracted}"
        return Finding(
            vuln_type=info.primary_tag,
            title=info.name or template.id,
            severity=info.severity,
            confidence=Confidence.FIRM,
            url=url,
            description=info.description
            or f"Template '{template.id}' matched at {url} (HTTP {status}).",
            remediation=info.remediation,
            cwe=info.cwe,
            scanner=f"template:{template.id}",
            evidence=Evidence(
                matched_at=matched_strings[0] if matched_strings else None,
                notes=notes,
                extra={k: str(v) for k, v in extracted.items()},
            ),
        )


__all__ = ["TemplateScanner", "render"]
