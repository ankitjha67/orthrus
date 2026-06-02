"""Dependency-confusion / supply-chain scanner (CWE-829).

When an app's build declares a dependency on a package name that is **not
claimed on the public registry**, an attacker can register that name on npm /
PyPI. The next build resolves the public package instead of the intended private
one and runs the attacker's install scripts — remote code execution inside the
build/CI pipeline (the 2021 Alex Birsan "dependency confusion" attack).

This scanner looks for dependency manifests the target accidentally exposes
(``package.json``, ``requirements.txt`` at the web root or in discovered
endpoints — a common misdeploy), extracts the declared dependency names, and
checks each against the public registry. A declared dependency that returns 404
is **claimable by anyone** and flagged; a scoped npm package (``@org/pkg``) whose
scope is unclaimed is the textbook high-confidence case.

Manifest fetches go through the scope-enforced HttpClient. Registry look-ups go
to registry.npmjs.org / pypi.org (verified TLS) — they query *about* a package
name and never touch the target.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from urllib.parse import quote, urljoin, urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.dependency-confusion")

SCANNER_NAME = "dependency-confusion"
MAX_DEPS = 60           # cap registry look-ups per scan
NPM_REGISTRY = "https://registry.npmjs.org/"
PYPI_JSON = "https://pypi.org/pypi/{}/json"

# Manifest filename -> ecosystem. Probed at the web root and matched against any
# discovered endpoint whose path ends in one of these names.
MANIFEST_PATHS: dict[str, str] = {
    "package.json": "npm",
    "requirements.txt": "pypi",
}

# requirements.txt: take the project name up to the first version/extra/marker char.
_REQ_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")


def parse_package_json(text: str) -> list[str]:
    """Extract declared dependency names from a package.json (all dep groups)."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    names: list[str] = []
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        section = data.get(key)
        if isinstance(section, dict):
            names.extend(str(n) for n in section)
    return list(dict.fromkeys(names))


def parse_requirements(text: str) -> list[str]:
    """Extract package names from a requirements.txt body."""
    names: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-", "git+", "http://", "https://", ".")):
            continue
        m = _REQ_NAME.match(line)
        if m:
            names.append(m.group(1).lower())
    return list(dict.fromkeys(names))


def parse_manifest(text: str, ecosystem: str) -> list[str]:
    if ecosystem == "npm":
        return parse_package_json(text)
    if ecosystem == "pypi":
        return parse_requirements(text)
    return []


def is_scoped_npm(name: str) -> bool:
    return name.startswith("@") and "/" in name


def _registry_url(name: str, ecosystem: str) -> str:
    if ecosystem == "pypi":
        return PYPI_JSON.format(quote(name, safe=""))
    # npm: scoped names encode the slash; bare names go through as-is.
    return NPM_REGISTRY + (name.replace("/", "%2f") if is_scoped_npm(name) else quote(name, safe="@"))


async def is_unclaimed(client: httpx.AsyncClient, name: str, ecosystem: str) -> bool | None:
    """True if ``name`` is absent (404) from the public registry — claimable.

    Returns None on a network/registry error so the caller can skip rather than
    false-positive.
    """
    try:
        resp = await client.get(_registry_url(name, ecosystem), follow_redirects=True)
    except httpx.HTTPError as exc:
        logger.debug("registry lookup failed for %s (%s): %s", name, ecosystem, exc)
        return None
    if resp.status_code == 404:
        return True
    if resp.status_code == 200:
        return False
    return None  # rate-limited / unexpected — don't guess


def _root_of(target: str) -> str:
    parts = urlsplit(target if "://" in target else f"//{target}")
    scheme = parts.scheme or "https"
    return f"{scheme}://{parts.netloc}/"


@register
class DependencyConfusionScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "dependency-confusion"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        manifests = await self._discover_manifests(ctx)
        if not manifests:
            return

        # (name, ecosystem) -> source manifest URL
        declared: dict[tuple[str, str], str] = {}
        for source_url, ecosystem, text in manifests:
            for name in parse_manifest(text, ecosystem):
                declared.setdefault((name, ecosystem), source_url)
        if not declared:
            return

        items = list(declared.items())[:MAX_DEPS]
        async with httpx.AsyncClient(timeout=15.0, headers={"User-Agent": "orthrus-depconf/1.0"}) as client:
            for (name, ecosystem), source_url in items:
                unclaimed = await is_unclaimed(client, name, ecosystem)
                if unclaimed:
                    yield self._finding(name, ecosystem, source_url)

    async def _discover_manifests(self, ctx: ScanContext) -> list[tuple[str, str, str]]:
        """Return (url, ecosystem, body) for each readable dependency manifest."""
        found: list[tuple[str, str, str]] = []
        seen: set[str] = set()

        candidates: list[tuple[str, str]] = []
        root = _root_of(ctx.config.target)
        for filename, ecosystem in MANIFEST_PATHS.items():
            candidates.append((urljoin(root, filename), ecosystem))
        # Any discovered endpoint that *is* a manifest (e.g. /static/package.json).
        for ep in getattr(ctx, "endpoints", []):
            tail = urlsplit(ep.url).path.rsplit("/", 1)[-1]
            if tail in MANIFEST_PATHS:
                candidates.append((ep.url, MANIFEST_PATHS[tail]))

        for url, ecosystem in candidates:
            if url in seen or not ctx.scope.is_allowed(url):
                continue
            seen.add(url)
            try:
                resp = await ctx.http.get(url, follow_redirects=True)
            except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL):
                continue
            if resp.status_code == 200 and resp.text.strip():
                found.append((url, ecosystem, resp.text))
        return found

    def _finding(self, name: str, ecosystem: str, source_url: str) -> Finding:
        scoped = ecosystem == "npm" and is_scoped_npm(name)
        registry = "npm" if ecosystem == "npm" else "PyPI"
        return Finding(
            vuln_type="dependency-confusion",
            title=f"Dependency confusion: unclaimed {registry} package '{name}'",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            url=source_url,
            description=(
                f"The dependency manifest at {source_url} declares '{name}', which is **not "
                f"registered on the public {registry} registry**. An attacker can publish a "
                f"package under that exact name; the next build/CI run may resolve the public "
                f"package instead of the intended private one and execute its install scripts — "
                f"remote code execution in the build pipeline (dependency confusion). "
                + (
                    "The npm scope is unclaimed, which is the classic high-impact case."
                    if scoped else ""
                )
            ),
            remediation=(
                f"Claim '{name}' on the public {registry} registry (a defensive placeholder), "
                "scope internal packages and pin them to your private registry with a strict "
                "resolver config (npm scoped-registry / pip --index-url + hash pinning), and "
                "enable lockfile integrity + signature verification in CI."
            ),
            cwe="CWE-829",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                request_raw=f"GET {_registry_url(name, ecosystem)}",
                notes=f"declared in {source_url}; public registry returned 404 (claimable)",
            ),
        )


__all__ = [
    "DependencyConfusionScanner",
    "parse_package_json",
    "parse_requirements",
    "parse_manifest",
    "is_scoped_npm",
    "is_unclaimed",
]
