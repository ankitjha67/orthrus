"""Exposed sensitive file scanner (PRD §5.5 git/env exposure).

Consumes endpoints that content discovery confirmed as exposed sensitive files
(``source="sensitive"``) and raises findings — no extra requests. Covers source
control (.git/.svn), environment files, backups, and server config.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from hydra.core.context import ScanContext
from hydra.core.schemas import Confidence, Evidence, Finding, Severity
from hydra.scanners.base_scanner import BaseScanner
from hydra.scanners.registry import register

SCANNER_NAME = "exposed-files"

_HIGH = (".env", ".git", ".svn", "wp-config", "backup", "db.sql", "database.sql", "config.json")


def _severity_for(path: str) -> Severity:
    lower = path.lower()
    if any(h in lower for h in _HIGH):
        return Severity.HIGH
    return Severity.MEDIUM


@register
class ExposedFilesScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "exposed-file"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        for ep in ctx.endpoints:
            if ep.source != "sensitive" or ep.url in seen:
                continue
            seen.add(ep.url)
            path = urlsplit(ep.url).path
            yield Finding(
                vuln_type="exposed-file",
                title=f"Exposed sensitive file: {path}",
                severity=_severity_for(path),
                confidence=Confidence.FIRM,
                url=ep.url,
                description=(
                    f"The sensitive file {path} is publicly accessible (HTTP "
                    f"{ep.response_status}). It may expose credentials, source code, or "
                    "internal configuration."
                ),
                remediation=(
                    "Remove the file from the web root or block access to it (deny dotfiles, "
                    "VCS directories, and backups at the server/CDN)."
                ),
                cwe="CWE-538",
                scanner=SCANNER_NAME,
                evidence=Evidence(matched_at=path, notes=f"HTTP {ep.response_status}"),
            )


__all__ = ["ExposedFilesScanner"]
