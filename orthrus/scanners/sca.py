"""Software-composition analysis (client-side *and* server-side).

Two scanners:

* ``SCAScanner`` (``sca-js-libraries``) - a retire.js-style check: fetch the
  JavaScript ORTHRUS discovered, fingerprint bundled library versions from their
  banners, and flag any below the fixed version for a known advisory.
* ``SCAManifestScanner`` (``sca-dependency-manifests``) - the server-side half.
  A black-box DAST target frequently *leaks* its dependency graph over HTTP: an
  exposed ``package-lock.json``, ``composer.lock``, ``requirements.txt``,
  ``Gemfile.lock`` or ``yarn.lock``. This scanner harvests those manifests at
  well-known paths, parses them into exact-pinned components across the npm /
  Composer / PyPI / RubyGems ecosystems, flags the exposure itself (the manifest
  hands an attacker your precise versions), and matches every component against a
  curated offline advisory rule set.

Both rule sets are intentionally small and high-confidence - the seed of a feed
``orthrus update`` can later refresh - so version comparison stays low-FP.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator, Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.sca")

SCANNER_NAME = "sca-js-libraries"
MAX_JS = 40


@dataclass(frozen=True)
class LibRule:
    name: str
    pattern: re.Pattern[str]
    fixed: str  # first non-vulnerable version ("999.0.0" => all versions affected / EOL)
    advisory: str
    severity: Severity
    cwe: str


# Distinctive banner/identifier patterns -> version capture group.
VULN_DB: tuple[LibRule, ...] = (
    LibRule(
        "jQuery",
        re.compile(r"jquery[ \-/]?v?(\d+\.\d+\.\d+)", re.IGNORECASE),
        "3.5.0",
        "jQuery < 3.5.0 is vulnerable to XSS via htmlPrefilter (CVE-2020-11022 / CVE-2020-11023).",
        Severity.MEDIUM,
        "CWE-79",
    ),
    LibRule(
        "lodash",
        re.compile(r"lodash[ \-/]?v?(\d+\.\d+\.\d+)", re.IGNORECASE),
        "4.17.21",
        "lodash < 4.17.21 is vulnerable to prototype pollution / command injection "
        "(CVE-2021-23337, CVE-2020-8203).",
        Severity.HIGH,
        "CWE-1321",
    ),
    LibRule(
        "Handlebars",
        re.compile(r"handlebars[ \-/]?v?(\d+\.\d+\.\d+)", re.IGNORECASE),
        "4.7.7",
        "Handlebars < 4.7.7 is vulnerable to prototype pollution leading to RCE in templates "
        "(CVE-2021-23369 / CVE-2019-19919).",
        Severity.HIGH,
        "CWE-1321",
    ),
    LibRule(
        "AngularJS",
        re.compile(r"angular(?:js)?[ \-/]?v?(\d+\.\d+\.\d+)", re.IGNORECASE),
        "999.0.0",  # AngularJS (1.x) is end-of-life and unpatched.
        "AngularJS (1.x) is end-of-life: no security patches; known XSS sandbox-escape issues.",
        Severity.MEDIUM,
        "CWE-1104",
    ),
)


def _ver(s: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", s)[:3])


def find_vulnerable_libs(js: str) -> list[dict[str, str]]:
    """Return one entry per distinct vulnerable library detected in ``js``."""
    hits: list[dict[str, str]] = []
    seen: set[str] = set()
    for rule in VULN_DB:
        m = rule.pattern.search(js)
        if not m or rule.name in seen:
            continue
        version = m.group(1)
        if _ver(version) < _ver(rule.fixed):
            seen.add(rule.name)
            hits.append(
                {
                    "name": rule.name,
                    "version": version,
                    "fixed": rule.fixed,
                    "advisory": rule.advisory,
                    "severity": rule.severity.value,
                    "cwe": rule.cwe,
                }
            )
    return hits


def _is_js_url(url: str) -> bool:
    return urlsplit(url).path.lower().endswith(".js")


@register
class SCAScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "vulnerable-component"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen_urls: set[str] = set()
        tested = 0

        for ep in ctx.endpoints:
            url = ep.url.split("#", 1)[0]
            if not _is_js_url(url) or url in seen_urls:
                continue
            if not ctx.scope.is_allowed(url):
                continue
            seen_urls.add(url)
            if tested >= MAX_JS:
                break
            tested += 1

            try:
                resp = await ctx.http.get(url, follow_redirects=True)
            except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
                logger.debug("sca fetch failed for %s: %s", url, exc)
                continue

            for hit in find_vulnerable_libs(resp.text):
                yield self._finding(url, hit)

    def _finding(self, url: str, hit: dict[str, str]) -> Finding:
        sev = Severity(hit["severity"])
        return Finding(
            vuln_type="vulnerable-component",
            title=f"Outdated/vulnerable JS library: {hit['name']} {hit['version']}",
            severity=sev,
            confidence=Confidence.FIRM,
            url=url,
            description=(
                f"{url} bundles {hit['name']} {hit['version']}. {hit['advisory']} "
                "Client-side libraries with known vulnerabilities expose users to XSS, "
                "prototype pollution, and other client-side attacks."
            ),
            remediation=(
                f"Upgrade {hit['name']} to {hit['fixed']} or later (or a maintained replacement) "
                "and keep front-end dependencies under continuous SCA monitoring."
            ),
            cwe=hit["cwe"],
            scanner=SCANNER_NAME,
            evidence=Evidence(
                matched_at=f"{hit['name']} {hit['version']}",
                notes=f"fixed in {hit['fixed']}",
            ),
        )


# ===========================================================================
# Server-side SCA: harvest leaked dependency manifests -> parse -> match
# ===========================================================================

MAX_MANIFEST_ORIGINS = 2


@dataclass(frozen=True)
class Component:
    ecosystem: str  # npm | composer | pypi | gem
    name: str
    version: str


@dataclass(frozen=True)
class PkgRule:
    ecosystem: str
    name: str
    fixed: str  # first non-vulnerable version ("999.0.0" => EOL / all affected)
    advisory: str
    severity: Severity
    cwe: str


# Curated, high-confidence advisories across the server-side ecosystems. Small
# on purpose (each is a clear name + single fixed version) to hold FP rate down.
PACKAGE_RULES: tuple[PkgRule, ...] = (
    # --- npm ---
    PkgRule("npm", "lodash", "4.17.21", "Prototype pollution / command injection (CVE-2021-23337).", Severity.HIGH, "CWE-1321"),
    PkgRule("npm", "minimist", "1.2.6", "Prototype pollution (CVE-2021-44906).", Severity.HIGH, "CWE-1321"),
    PkgRule("npm", "node-fetch", "2.6.7", "Exposure of sensitive information via redirect (CVE-2022-0235).", Severity.MEDIUM, "CWE-200"),
    PkgRule("npm", "ejs", "3.1.7", "Server-side template injection -> RCE (CVE-2022-29078).", Severity.HIGH, "CWE-94"),
    PkgRule("npm", "async", "2.6.4", "Prototype pollution (CVE-2021-43138).", Severity.HIGH, "CWE-1321"),
    # --- PyPI ---
    PkgRule("pypi", "django", "3.2.14", "Multiple advisories incl. SQL injection (CVE-2022-34265).", Severity.HIGH, "CWE-89"),
    PkgRule("pypi", "flask", "2.2.5", "Cookie/session data exposure via caching proxies (CVE-2023-30861).", Severity.MEDIUM, "CWE-200"),
    PkgRule("pypi", "requests", "2.31.0", "Proxy-Authorization header leak on redirect (CVE-2023-32681).", Severity.MEDIUM, "CWE-200"),
    PkgRule("pypi", "pyyaml", "5.4", "Arbitrary code execution via full_load/load (CVE-2020-14343).", Severity.HIGH, "CWE-20"),
    PkgRule("pypi", "werkzeug", "2.2.3", "DoS via multipart parsing / debugger PIN (CVE-2023-25577).", Severity.MEDIUM, "CWE-400"),
    PkgRule("pypi", "jinja2", "2.11.3", "ReDoS in the urlize filter (CVE-2020-28493).", Severity.MEDIUM, "CWE-400"),
    # --- Composer (PHP) ---
    PkgRule("composer", "guzzlehttp/guzzle", "7.4.5", "Cross-domain cookie / Authorization leak on redirect (CVE-2022-31090).", Severity.MEDIUM, "CWE-200"),
    PkgRule("composer", "symfony/http-kernel", "5.4.20", "Multiple advisories incl. cache poisoning.", Severity.MEDIUM, "CWE-200"),
    # --- RubyGems ---
    PkgRule("gem", "rack", "2.2.6.1", "DoS via multipart / crafted headers (CVE-2022-44570/44571).", Severity.MEDIUM, "CWE-400"),
    PkgRule("gem", "nokogiri", "1.13.9", "Bundled libxml2 vulnerabilities (CVE-2022-40304 et al.).", Severity.HIGH, "CWE-787"),
)

_PKG_RULE_INDEX: dict[tuple[str, str], PkgRule] = {
    (r.ecosystem, r.name.lower()): r for r in PACKAGE_RULES
}


def _dedupe(components: Iterable[Component]) -> list[Component]:
    seen: set[tuple[str, str, str]] = set()
    out: list[Component] = []
    for c in components:
        key = (c.ecosystem, c.name.lower(), c.version)
        if c.name and c.version and key not in seen:
            seen.add(key)
            out.append(c)
    return out


def parse_package_lock(text: str) -> list[Component]:
    """npm package-lock.json / npm-shrinkwrap.json (lockfile v1, v2 and v3)."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    comps: list[Component] = []
    packages = data.get("packages") if isinstance(data, dict) else None
    if isinstance(packages, dict):  # v2/v3
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict):
                continue
            name = path.split("node_modules/")[-1]
            ver = meta.get("version")
            if name and ver:
                comps.append(Component("npm", name, str(ver)))

    def _walk(deps: dict) -> None:  # v1 nested dependencies
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            ver = meta.get("version")
            if ver:
                comps.append(Component("npm", name, str(ver)))
            sub = meta.get("dependencies")
            if isinstance(sub, dict):
                _walk(sub)

    deps = data.get("dependencies") if isinstance(data, dict) else None
    if isinstance(deps, dict):
        _walk(deps)
    return _dedupe(comps)


def parse_composer_lock(text: str) -> list[Component]:
    """PHP composer.lock (packages + packages-dev)."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    comps: list[Component] = []
    for key in ("packages", "packages-dev"):
        for pkg in data.get(key, []) or []:
            if not isinstance(pkg, dict):
                continue
            name, ver = pkg.get("name"), pkg.get("version")
            if name and ver:
                comps.append(Component("composer", name, str(ver).lstrip("vV")))
    return _dedupe(comps)


_REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([0-9][A-Za-z0-9.\-]*)")


def parse_requirements(text: str) -> list[Component]:
    """Python requirements.txt - only exact `==` pins are matchable."""
    comps: list[Component] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        m = _REQ_RE.match(line)
        if m:
            comps.append(Component("pypi", m.group(1).lower(), m.group(2)))
    return _dedupe(comps)


_GEM_SPEC_RE = re.compile(r"^    ([A-Za-z0-9._-]+) \(([0-9][0-9A-Za-z.\-]*)\)$")


def parse_gemfile_lock(text: str) -> list[Component]:
    """Ruby Gemfile.lock - top-level specs (4-space indent, exact versions)."""
    comps: list[Component] = []
    for raw in text.splitlines():
        m = _GEM_SPEC_RE.match(raw.rstrip())
        if m:
            comps.append(Component("gem", m.group(1).lower(), m.group(2)))
    return _dedupe(comps)


_YARN_VER_RE = re.compile(r'version\s+"?([0-9][\w.\-]*)"?')


def parse_yarn_lock(text: str) -> list[Component]:
    """yarn.lock (v1) - block header carries the name, `version "x"` the pin."""
    comps: list[Component] = []
    name: str | None = None
    for raw in text.splitlines():
        if raw and not raw[0].isspace() and raw.rstrip().endswith(":"):
            first = raw.split(",")[0].strip().rstrip(":").strip().strip('"')
            at = first.rfind("@")
            name = first[:at] if at > 0 else first  # keep scoped @scope/name
        elif name and raw.strip().startswith("version"):
            m = _YARN_VER_RE.search(raw)
            if m:
                comps.append(Component("npm", name, m.group(1)))
                name = None
    return _dedupe(comps)


# (path, ecosystem label for the exposure finding, parser)
MANIFESTS: tuple[tuple[str, str, Callable[[str], list[Component]]], ...] = (
    ("/package-lock.json", "npm", parse_package_lock),
    ("/npm-shrinkwrap.json", "npm", parse_package_lock),
    ("/yarn.lock", "npm", parse_yarn_lock),
    ("/composer.lock", "Composer", parse_composer_lock),
    ("/requirements.txt", "PyPI", parse_requirements),
    ("/Gemfile.lock", "RubyGems", parse_gemfile_lock),
)


def match_components(components: Iterable[Component]) -> list[dict[str, str]]:
    """Match harvested components against PACKAGE_RULES (exact-name, version <)."""
    hits: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for c in components:
        rule = _PKG_RULE_INDEX.get((c.ecosystem, c.name.lower()))
        if rule is None or not _ver(c.version):
            continue
        if _ver(c.version) < _ver(rule.fixed):
            key = (c.ecosystem, c.name.lower())
            if key in seen:
                continue
            seen.add(key)
            hits.append(
                {
                    "ecosystem": c.ecosystem,
                    "name": c.name,
                    "version": c.version,
                    "fixed": rule.fixed,
                    "advisory": rule.advisory,
                    "severity": rule.severity.value,
                    "cwe": rule.cwe,
                }
            )
    return hits


def _origins(target: str, endpoint_urls: Iterable[str]) -> list[str]:
    seen: list[str] = []
    for url in (target, *endpoint_urls):
        parts = urlsplit(url)
        if parts.scheme and parts.netloc:
            origin = f"{parts.scheme}://{parts.netloc}"
            if origin not in seen:
                seen.append(origin)
    return seen


@register
class SCAManifestScanner(BaseScanner):
    name = "sca-dependency-manifests"
    vuln_type = "vulnerable-component"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        origins = _origins(ctx.config.target, [ep.url for ep in ctx.endpoints])
        for origin in origins[:MAX_MANIFEST_ORIGINS]:
            for path, ecosystem, parser in MANIFESTS:
                url = origin + path
                if not ctx.scope.is_allowed(url):
                    continue
                resp = await self._get(ctx, url)
                if resp is None or resp.status_code != 200:
                    continue
                components = parser(resp.text)
                if not components:
                    continue  # 200 but not a real manifest (soft-404 / HTML)
                yield self._exposure_finding(url, ecosystem, len(components))
                for hit in match_components(components):
                    yield self._component_finding(url, hit)

    async def _get(self, ctx: ScanContext, url: str) -> httpx.Response | None:
        try:
            return await ctx.http.get(url, follow_redirects=False)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("sca manifest fetch failed for %s: %s", url, exc)
            return None

    def _exposure_finding(self, url: str, ecosystem: str, count: int) -> Finding:
        return Finding(
            vuln_type="info-disclosure",
            title=f"Exposed dependency manifest ({ecosystem}): {urlsplit(url).path}",
            severity=Severity.MEDIUM,
            confidence=Confidence.FIRM,
            url=url,
            description=(
                f"The {ecosystem} dependency manifest at {urlsplit(url).path} is publicly reachable "
                f"and lists {count} pinned components. A lockfile hands an attacker your exact "
                "dependency versions, letting them map known CVEs to your stack without probing - "
                "and can reveal internal/private package names for a dependency-confusion attack."
            ),
            remediation=(
                "Do not deploy lockfiles/manifests to the web root; block them at the server or CDN "
                "(deny package-lock.json, composer.lock, requirements.txt, Gemfile.lock, yarn.lock). "
                "Serve the application from a build artifact that excludes development metadata."
            ),
            cwe="CWE-200",
            scanner=self.name,
            evidence=Evidence(
                matched_at=urlsplit(url).path,
                notes=f"{count} pinned {ecosystem} components parsed from the exposed manifest",
            ),
        )

    def _component_finding(self, url: str, hit: dict[str, str]) -> Finding:
        return Finding(
            vuln_type="vulnerable-component",
            title=f"Vulnerable dependency: {hit['name']} {hit['version']} ({hit['ecosystem']})",
            severity=Severity(hit["severity"]),
            confidence=Confidence.FIRM,
            url=url,
            description=(
                f"The exposed manifest at {urlsplit(url).path} pins {hit['name']} "
                f"{hit['version']} ({hit['ecosystem']}). {hit['advisory']} The version is below the "
                f"fixed release {hit['fixed']}."
            ),
            remediation=(
                f"Upgrade {hit['name']} to {hit['fixed']} or later and adopt continuous SCA so "
                "vulnerable dependencies are caught in CI before deployment."
            ),
            cwe=hit["cwe"],
            scanner=self.name,
            evidence=Evidence(
                matched_at=f"{hit['name']} {hit['version']}",
                notes=f"{hit['ecosystem']} advisory; fixed in {hit['fixed']}",
            ),
        )


__all__ = [
    "SCAScanner",
    "SCAManifestScanner",
    "find_vulnerable_libs",
    "VULN_DB",
    "Component",
    "PkgRule",
    "PACKAGE_RULES",
    "match_components",
    "parse_package_lock",
    "parse_composer_lock",
    "parse_requirements",
    "parse_gemfile_lock",
    "parse_yarn_lock",
]
