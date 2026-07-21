"""Software-composition analysis: known-vulnerable front-end JS libraries.

A retire.js-style check: fetch the JavaScript ORTHRUS discovered, fingerprint
the bundled library versions from their banners/identifiers, and flag any that
fall below the fixed version for a known advisory (XSS, prototype pollution,
end-of-life). Pure version comparison - no network beyond fetching the already
in-scope ``.js`` assets.

The rule set is intentionally small and high-confidence (each library has a
distinctive banner and a single clear fixed version) to keep false positives
low; it is the seed of a feed that ``orthrus update`` can later refresh.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
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


__all__ = ["SCAScanner", "find_vulnerable_libs", "VULN_DB"]
