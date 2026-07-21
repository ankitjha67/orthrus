"""Nikto adapter - run the classic web-server scanner and normalize its JSON.

Nikto checks a web server for thousands of dangerous files, outdated components,
and server misconfigurations. It's noisy and unranked by design, so this adapter
maps each item to a *conservatively*-rated Finding (default LOW/INFO) and only
promotes to MEDIUM when the message clearly names an exploitable class
(injection, traversal, RCE, disclosure). vuln_type is inferred from the message
so items flow into the same triage/chain pipeline as native findings.
"""

from __future__ import annotations

import json

from orthrus.core.schemas import Evidence, Finding, Severity
from orthrus.integrations.base import ExternalToolAdapter, register_tool

# Keyword → (vuln_type, severity). First match wins; order = most-specific first.
_CLASSIFIERS: tuple[tuple[tuple[str, ...], str, Severity], ...] = (
    (("sql injection", "sqli"), "sqli", Severity.MEDIUM),
    (("cross-site scripting", "xss"), "xss", Severity.MEDIUM),
    (("remote file", "command execution", "rce", "code execution"), "cmd-injection", Severity.MEDIUM),
    (("traversal", "../", "local file", "file inclusion"), "lfi", Severity.MEDIUM),
    (("crlf",), "crlf-injection", Severity.MEDIUM),
    (("directory indexing", "directory listing", "index of"), "directory-listing", Severity.LOW),
    (("backup", ".git", ".svn", "config", "phpinfo", "readme", "changelog"), "exposed-file", Severity.LOW),
    (("default", "sample", "test file"), "exposed-file", Severity.LOW),
    (("x-frame-options", "x-content-type", "strict-transport", "content-security",
      "header is not", "header not"), "security-headers", Severity.INFO),
    (("cookie",), "auth-session", Severity.INFO),
    (("outdated", "is out of date", "appears to be", "vulnerable"), "vulnerable-component", Severity.LOW),
)


def _classify(msg: str) -> tuple[str, Severity]:
    low = (msg or "").lower()
    for needles, vuln_type, sev in _CLASSIFIERS:
        if any(n in low for n in needles):
            return vuln_type, sev
    return "web-server-issue", Severity.LOW


def _iter_vulns(stdout: str):
    """Yield nikto vuln dicts; tolerate array-of-hosts or single-host object."""
    text = (stdout or "").strip()
    if not text:
        return
    try:
        data = json.loads(text)
    except ValueError:
        return
    hosts = data if isinstance(data, list) else [data]
    for host in hosts:
        if not isinstance(host, dict):
            continue
        for v in host.get("vulnerabilities", []) or []:
            if isinstance(v, dict):
                yield host, v


def parse_nikto_json(stdout: str, target: str) -> list[Finding]:
    """Map nikto JSON items to conservatively-rated Findings (pure)."""
    findings: list[Finding] = []
    for host, v in _iter_vulns(stdout):
        msg = str(v.get("msg") or v.get("message") or "").strip()
        if not msg:
            continue
        vuln_type, sev = _classify(msg)
        path = str(v.get("url") or v.get("uri") or "/")
        base = str(host.get("host") or target).rstrip("/")
        url = path if path.startswith("http") else base + (path if path.startswith("/") else "/" + path)
        ref = v.get("OSVDB") or v.get("references") or v.get("id")
        findings.append(
            Finding(
                vuln_type=vuln_type,
                title=f"[nikto] {msg[:120]}",
                severity=sev,
                url=url,
                description=(
                    f"Nikto reported: {msg}. Nikto checks are pattern-based and unranked - "
                    "confirm manually before reporting; treat this as a lead, not a proof."
                )[:600],
                remediation="Review the flagged resource/header; remove or restrict it if unneeded.",
                scanner="nikto",
                evidence=Evidence(
                    matched_at=f"{v.get('method', 'GET')} {url}",
                    notes=f"nikto id={v.get('id', '?')} ref={ref}",
                ),
            )
        )
    return findings


@register_tool
class NiktoAdapter(ExternalToolAdapter):
    name = "nikto"
    binary = "nikto"
    default_timeout = 900.0

    def build_command(self, target: str) -> list[str]:
        return [self.binary, "-h", target, "-Format", "json", "-output", "-", "-nointeractive"]

    def parse_output(self, stdout: str, target: str) -> list[Finding]:
        return parse_nikto_json(stdout, target)


__all__ = ["NiktoAdapter", "parse_nikto_json"]
