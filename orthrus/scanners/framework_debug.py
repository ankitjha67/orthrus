"""Framework debug / management-endpoint exposure scanner.

Production apps routinely ship with framework debug features or management
endpoints left reachable: Spring Boot Actuator (``/actuator/env`` leaks config
and secrets), ``phpinfo()``, Apache ``server-status``, Prometheus ``/metrics``,
Laravel Telescope, Rails info pages - and, worst of all, **debug mode** that
renders full stack traces (Flask/Werkzeug, Django, Laravel Ignition, Rails) and
leaks source, file paths, and sometimes an interactive console.

Two probes, both non-mutating GETs through the scope-enforced HttpClient:

1. **Known endpoints** - a curated path list, each confirmed by a *content*
   fingerprint (not just a 200) so a generic catch-all page can't false-positive.
2. **Debug mode** - request a deliberately non-existent path and look for a
   framework stack-trace/debugger marker in the error response.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.framework-debug")

SCANNER_NAME = "framework-debug-exposure"
MAX_ORIGINS = 3
MAX_REQUESTS = 40

# A path unlikely to exist, used to trigger a framework error page.
_ERROR_PROBE_PATH = "/orthrus-debug-probe-7f3a"

# (path, framework label, content signatures (any match), severity)
DEBUG_PROBES: tuple[tuple[str, str, tuple[str, ...], Severity], ...] = (
    ("/actuator/env", "Spring Boot Actuator (env)", ("propertySources",), Severity.HIGH),
    ("/actuator", "Spring Boot Actuator", ('"_links"', "actuator"), Severity.MEDIUM),
    ("/actuator/health", "Spring Boot Actuator (health)", ('"status":"up"',), Severity.LOW),
    ("/phpinfo.php", "phpinfo()", ("phpinfo()", "PHP Version"), Severity.MEDIUM),
    ("/info.php", "phpinfo()", ("phpinfo()", "PHP Version"), Severity.MEDIUM),
    ("/server-status", "Apache server-status", ("Apache Server Status", "Server uptime"), Severity.MEDIUM),
    ("/metrics", "Prometheus metrics", ("# HELP", "# TYPE"), Severity.LOW),
    ("/telescope/requests", "Laravel Telescope", ("Telescope", "laravel"), Severity.MEDIUM),
    ("/rails/info/routes", "Rails info", ("URI Pattern", "Routing Error"), Severity.MEDIUM),
)

# Markers that prove framework debug mode (stack traces / debuggers) is enabled.
_DEBUG_MODE_MARKERS: tuple[tuple[str, str], ...] = (
    ("Werkzeug Debugger", "Flask/Werkzeug debugger"),
    ("Traceback (most recent call last)", "Python stack trace (debug mode)"),
    ("DEBUG = True", "Django debug mode"),
    ("You're seeing this error because you have", "Django debug mode"),
    ("Whoops, looks like something went wrong", "Laravel/Symfony debug page"),
    ("Ignition", "Laravel Ignition debug page"),
    ("ActionController::RoutingError", "Rails debug mode"),
    ("Rack::", "Rack stack trace (debug mode)"),
)


def match_probe(signatures: Iterable[str], status: int, body: str) -> bool:
    """True if the endpoint returned 200 and the body matches a signature."""
    if status != 200:
        return False
    low = body.lower()
    return any(sig.lower() in low for sig in signatures)


def detect_debug_mode(body: str) -> str | None:
    """Return a framework label if the body reveals an enabled debugger/stack trace."""
    for marker, label in _DEBUG_MODE_MARKERS:
        if marker in body:
            return label
    return None


def origins_from(target: str, endpoint_urls: Iterable[str]) -> list[str]:
    """Distinct ``scheme://host`` origins from the target + discovered endpoints."""
    seen: list[str] = []
    for url in (target, *endpoint_urls):
        parts = urlsplit(url)
        if parts.scheme and parts.netloc:
            origin = f"{parts.scheme}://{parts.netloc}"
            if origin not in seen:
                seen.append(origin)
    return seen


@register
class FrameworkDebugScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "framework-debug"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        emitted: set[tuple[str, str]] = set()
        requests = 0
        origins = origins_from(ctx.config.target, [ep.url for ep in ctx.endpoints])[:MAX_ORIGINS]

        for origin in origins:
            # 1) Debug-mode (stack trace / debugger) via a bogus path.
            if requests < MAX_REQUESTS and ctx.scope.is_allowed(origin + _ERROR_PROBE_PATH):
                requests += 1
                resp = await self._get(ctx, origin + _ERROR_PROBE_PATH)
                if resp is not None:
                    label = detect_debug_mode(resp.text)
                    if label and (origin, "debug-mode") not in emitted:
                        emitted.add((origin, "debug-mode"))
                        yield self._debug_mode_finding(origin + _ERROR_PROBE_PATH, label)

            # 2) Known management/debug endpoints, confirmed by content.
            for path, framework, signatures, severity in DEBUG_PROBES:
                if requests >= MAX_REQUESTS:
                    break
                url = origin + path
                if not ctx.scope.is_allowed(url):
                    continue
                requests += 1
                resp = await self._get(ctx, url)
                if resp is None or not match_probe(signatures, resp.status_code, resp.text):
                    continue
                key = (origin, path)
                if key in emitted:
                    continue
                emitted.add(key)
                yield self._endpoint_finding(url, path, framework, severity)

    async def _get(self, ctx: ScanContext, url: str) -> httpx.Response | None:
        try:
            return await ctx.http.get(url, follow_redirects=False)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("framework-debug probe failed for %s: %s", url, exc)
            return None

    def _endpoint_finding(self, url: str, path: str, framework: str, severity: Severity) -> Finding:
        return Finding(
            vuln_type="framework-debug",
            title=f"Exposed framework/management endpoint: {framework} ({path})",
            severity=severity,
            confidence=Confidence.FIRM,
            url=url,
            description=(
                f"The {framework} endpoint at {path} is publicly reachable and returned its "
                "expected content. Management and framework endpoints commonly expose "
                "configuration, environment variables and secrets, runtime metrics, request "
                "history, or internal routes - valuable reconnaissance and, for some (e.g. "
                "Actuator env/heapdump), a direct path to credential disclosure or RCE."
            ),
            remediation=(
                "Disable the endpoint in production or bind it to an internal interface; require "
                "authentication and restrict by network. For Spring Boot, expose only required "
                "actuators and secure them; remove phpinfo()/server-status from public hosts."
            ),
            cwe="CWE-200",
            scanner=SCANNER_NAME,
            evidence=Evidence(matched_at=path, notes=f"{framework} content fingerprint matched"),
        )

    def _debug_mode_finding(self, url: str, label: str) -> Finding:
        return Finding(
            vuln_type="framework-debug",
            title=f"Debug mode enabled ({label})",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            url=url,
            description=(
                f"A request to a non-existent path returned a {label}. Debug mode renders full "
                "stack traces that leak source code, file-system paths, library versions, and "
                "configuration; some debuggers (e.g. Werkzeug) expose an interactive console "
                "that can lead to remote code execution."
            ),
            remediation=(
                "Disable debug mode in production (e.g. Flask DEBUG=False, Django DEBUG=False, "
                "APP_DEBUG=false). Serve generic error pages and log details server-side only."
            ),
            cwe="CWE-489",
            scanner=SCANNER_NAME,
            evidence=Evidence(matched_at=label, notes="stack-trace/debugger marker in error page"),
        )


__all__ = [
    "FrameworkDebugScanner",
    "match_probe",
    "detect_debug_mode",
    "origins_from",
    "DEBUG_PROBES",
]
