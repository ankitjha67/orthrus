"""WPScan adapter — normalize WPScan's JSON into ORTHRUS Findings.

WordPress is ubiquitous in bounty scope and WPScan is the standard scanner for
it. This adapter maps the three things WPScan actually finds — a vulnerable core
version, vulnerable plugins/themes, and "interesting findings" (exposed
readme/debug-log/directory-listing) — into Findings, carrying CVE references and
the fixed-in version so a report is actionable.
"""

from __future__ import annotations

import json

from orthrus.core.schemas import Confidence, Evidence, Finding, Severity
from orthrus.integrations.base import ExternalToolAdapter, register_tool

# interesting_findings 'type' → (vuln_type, severity)
_INTERESTING = {
    "directorylisting": ("directory-listing", Severity.LOW),
    "listing": ("directory-listing", Severity.LOW),
    "debug_log": ("exposed-file", Severity.MEDIUM),
    "backup_db": ("exposed-file", Severity.HIGH),
    "readme": ("exposed-file", Severity.INFO),
    "headers": ("security-headers", Severity.INFO),
    "xmlrpc": ("api-misconfig", Severity.LOW),
    "wp_cron": ("api-misconfig", Severity.INFO),
    "upload_directory": ("directory-listing", Severity.LOW),
}


def _cves(refs: dict) -> list[str]:
    cve = (refs or {}).get("cve") or []
    return [f"CVE-{c}" if not str(c).upper().startswith("CVE") else str(c) for c in cve]


def _vuln_findings(vulns, *, component: str, base_url: str) -> list[Finding]:
    out: list[Finding] = []
    for v in vulns or []:
        if not isinstance(v, dict):
            continue
        title = str(v.get("title") or "Known vulnerability").strip()
        cves = _cves(v.get("references", {}))
        fixed = v.get("fixed_in")
        out.append(
            Finding(
                vuln_type="vulnerable-component",
                title=f"[wpscan] {component}: {title}"[:140],
                severity=Severity.HIGH if cves else Severity.MEDIUM,
                confidence=Confidence.FIRM,
                url=base_url,
                description=(
                    f"WPScan matched a known vulnerability in {component}: {title}. "
                    + (f"References: {', '.join(cves)}. " if cves else "")
                    + (f"Fixed in {fixed}. " if fixed else "")
                    + "Confirm the running version is actually affected before reporting."
                )[:600],
                remediation=(f"Update {component} to {fixed} or later." if fixed
                             else f"Update {component} to the latest patched release."),
                cwe="CWE-1035",
                scanner="wpscan",
                evidence=Evidence(notes=f"wpscan {component}; cves={cves}; fixed_in={fixed}"),
            )
        )
    return out


def parse_wpscan_json(stdout: str, target: str) -> list[Finding]:
    """Map WPScan JSON output to Findings (pure)."""
    text = (stdout or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    base = str(data.get("target_url") or target)
    findings: list[Finding] = []

    version = data.get("version") or {}
    if isinstance(version, dict):
        num = version.get("number") or "?"
        findings += _vuln_findings(version.get("vulnerabilities"),
                                   component=f"WordPress core {num}", base_url=base)

    for key in ("main_theme", "plugins", "themes"):
        section = data.get(key)
        if isinstance(section, dict):
            # plugins/themes: dict of slug -> {version, vulnerabilities}; main_theme: one dict
            entries = section.values() if key != "main_theme" else [section]
            for comp in entries:
                if not isinstance(comp, dict):
                    continue
                slug = comp.get("slug") or comp.get("style_name") or key
                findings += _vuln_findings(comp.get("vulnerabilities"),
                                           component=str(slug), base_url=base)

    for item in data.get("interesting_findings") or []:
        if not isinstance(item, dict):
            continue
        itype = str(item.get("type") or "").lower()
        vuln_type, sev = _INTERESTING.get(itype, (None, None))
        if vuln_type is None:
            continue
        findings.append(
            Finding(
                vuln_type=vuln_type,
                title=f"[wpscan] {item.get('to_s') or itype}"[:140],
                severity=sev,
                url=str(item.get("url") or base),
                description=str(item.get("to_s") or f"WPScan interesting finding: {itype}")[:600],
                remediation="Restrict or remove the exposed resource if it isn't required.",
                scanner="wpscan",
                evidence=Evidence(notes=f"wpscan interesting_finding type={itype}"),
            )
        )
    return findings


@register_tool
class WpscanAdapter(ExternalToolAdapter):
    name = "wpscan"
    binary = "wpscan"
    default_timeout = 900.0

    def build_command(self, target: str) -> list[str]:
        return [self.binary, "--url", target, "--format", "json", "--no-banner",
                "--no-update", "--enumerate", "vp,vt,cb,dbe"]

    def parse_output(self, stdout: str, target: str) -> list[Finding]:
        return parse_wpscan_json(stdout, target)


__all__ = ["WpscanAdapter", "parse_wpscan_json"]
