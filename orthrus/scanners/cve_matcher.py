"""CVE matching against fingerprinted components (PRD §6.8 CVE Matching).

Correlates recon technology fingerprints (product + version) with the NVD CVE
database (REST API 2.0). Responses are cached on disk so repeat scans and
offline runs work. NVD queries go to nvd.nist.gov (a trusted data source), not
the target, so they intentionally bypass the target scope.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass

import httpx

from orthrus.core.config import get_settings
from orthrus.core.context import ScanContext
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.intel.cve_intel import enrich, escalate_severity, summary
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger

logger = get_logger("scanner.cve")

SCANNER_NAME = "cve"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_COMPONENTS = 10
MAX_CVES_PER_COMPONENT = 8

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "NONE": Severity.INFO,
}


@dataclass
class CveMatch:
    cve_id: str
    severity: Severity
    score: float | None
    vector: str | None
    description: str


def _version_tuple(value: str) -> tuple[int, ...]:
    parts: list[int] = []
    for chunk in re.split(r"[.\-+_]", value):
        m = re.match(r"\d+", chunk)
        parts.append(int(m.group()) if m else 0)
    return tuple(parts) or (0,)


def _ver_ge(a: str, b: str) -> bool:
    return _version_tuple(a) >= _version_tuple(b)


def _ver_gt(a: str, b: str) -> bool:
    return _version_tuple(a) > _version_tuple(b)


def _version_in_cpe(version: str, cpe: dict) -> bool:
    criteria = cpe.get("criteria", "")
    fields = criteria.split(":")
    cpe_version = fields[5] if len(fields) > 5 else "*"
    if cpe_version not in ("*", "-", "") and version == cpe_version:
        return True
    start_inc = cpe.get("versionStartIncluding")
    start_exc = cpe.get("versionStartExcluding")
    end_inc = cpe.get("versionEndIncluding")
    end_exc = cpe.get("versionEndExcluding")
    if not any((start_inc, start_exc, end_inc, end_exc)):
        return False
    ok = True
    if start_inc and not _ver_ge(version, start_inc):
        ok = False
    if start_exc and not _ver_gt(version, start_exc):
        ok = False
    if end_inc and _ver_gt(version, end_inc):
        ok = False
    if end_exc and not (_ver_gt(end_exc, version)):
        ok = False
    return ok


def _version_matches(version: str, cve: dict) -> bool:
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                if cpe.get("vulnerable", True) and _version_in_cpe(version, cpe):
                    return True
    return False


def _cvss(cve: dict) -> tuple[float | None, Severity, str | None]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            entry = arr[0]
            data = entry.get("cvssData", {})
            severity = entry.get("baseSeverity") or data.get("baseSeverity") or "MEDIUM"
            return data.get("baseScore"), _SEVERITY_MAP.get(severity.upper(), Severity.MEDIUM), data.get("vectorString")
    return None, Severity.MEDIUM, None


def _description(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def match_cves(product: str, version: str, nvd_json: dict) -> list[CveMatch]:
    """Pure: extract CVEs from an NVD response whose CPE version range covers ``version``."""
    matches: list[CveMatch] = []
    for item in nvd_json.get("vulnerabilities", []):
        cve = item.get("cve", {})
        if not _version_matches(version, cve):
            continue
        score, severity, vector = _cvss(cve)
        matches.append(
            CveMatch(cve.get("id", "CVE-?"), severity, score, vector, _description(cve))
        )
    return matches


def _cache_path(data_dir: str) -> str:
    return os.path.join(data_dir, "nvd_cache.json")


def _load_cache(data_dir: str) -> dict:
    try:
        with open(_cache_path(data_dir), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(data_dir: str, cache: dict) -> None:
    try:
        os.makedirs(data_dir, exist_ok=True)
        with open(_cache_path(data_dir), "w", encoding="utf-8") as fh:
            json.dump(cache, fh)
    except OSError:
        pass


@register
class CveMatcher(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "cve"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        settings = get_settings()
        cache = _load_cache(settings.data_dir)
        headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}

        seen: set[str] = set()
        components = 0
        async with httpx.AsyncClient(timeout=20.0, headers=headers) as client:
            for asset in ctx.assets:
                for tech in asset.technologies:
                    if not tech.version or components >= MAX_COMPONENTS:
                        continue
                    key = f"{tech.name}:{tech.version}".lower()
                    if key in seen:
                        continue
                    seen.add(key)
                    components += 1

                    nvd_json = cache.get(key)
                    if nvd_json is None:
                        nvd_json = await self._query(client, tech.name, tech.version)
                        if nvd_json is not None:
                            cache[key] = nvd_json
                    if not nvd_json:
                        continue

                    for m in match_cves(tech.name, tech.version, nvd_json)[:MAX_CVES_PER_COMPONENT]:
                        intel = enrich(m.cve_id)
                        tag = summary(intel)
                        yield Finding(
                            vuln_type="cve",
                            title=f"{m.cve_id} affects {tech.name} {tech.version}"
                            + (" [KEV]" if intel.kev else ""),
                            severity=escalate_severity(m.severity, intel),
                            # Known-exploited CVEs are firm prioritisation signals, not tentative.
                            confidence=Confidence.FIRM if intel.kev else Confidence.TENTATIVE,
                            url=ctx.config.target,
                            description=(
                                (f"{tag} " if tag else "")
                                + f"Fingerprinted {tech.name} {tech.version} matches {m.cve_id}: "
                                f"{m.description[:300]}"
                            ),
                            remediation=f"Upgrade {tech.name} to a patched version; review {m.cve_id}.",
                            cwe=None,
                            cvss_score=m.score,
                            cvss_vector=m.vector,
                            scanner=SCANNER_NAME,
                            evidence=Evidence(
                                matched_at=m.cve_id,
                                notes=f"NVD match for {key}" + (f" {tag}" if tag else ""),
                            ),
                        )

        _save_cache(settings.data_dir, cache)

    async def _query(self, client: httpx.AsyncClient, product: str, version: str) -> dict | None:
        params = {"keywordSearch": f"{product} {version}", "resultsPerPage": 50}
        try:
            resp = await client.get(NVD_API, params=params)
            if resp.status_code == 200:
                return resp.json()
            logger.debug("NVD returned %s for %s %s", resp.status_code, product, version)
        except (httpx.HTTPError, ValueError) as exc:
            logger.debug("NVD query failed for %s %s: %s", product, version, exc)
        return None


__all__ = ["CveMatcher", "match_cves", "CveMatch"]
