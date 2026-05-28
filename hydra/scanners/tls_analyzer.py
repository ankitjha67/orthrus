"""SSL/TLS configuration scanner (PRD §6.8 TLS/SSL).

Uses sslyze to enumerate supported protocol versions, weak cipher suites, and
certificate problems for HTTPS targets. sslyze opens its own TLS connections, so
the host is scope-validated first. The network/sslyze layer is isolated and
defensive (degrades to no findings on error); the verdict logic is pure and
unit-tested in ``classify_tls``.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from urllib.parse import urlsplit

from hydra.core.context import ScanContext
from hydra.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from hydra.scanners.base_scanner import BaseScanner
from hydra.scanners.registry import register
from hydra.utils.logger import get_logger

logger = get_logger("scanner.tls")

SCANNER_NAME = "tls"
WEAK_CIPHER_KEYWORDS = ("RC4", "_DES_", "3DES", "DES_CBC", "NULL", "EXPORT", "_MD5", "ANON", "_anon_")

_REMEDIATION = "Disable legacy protocols/ciphers; serve TLS 1.2+ with modern AEAD suites and a valid CA-issued certificate."


def classify_tls(facts: dict) -> list[tuple[Severity, str, str, str]]:
    """Map observed TLS facts to (severity, title, detail, cwe) issues."""
    issues: list[tuple[Severity, str, str, str]] = []
    if facts.get("sslv2"):
        issues.append((Severity.HIGH, "SSL 2.0 supported", "SSLv2 is broken and must be disabled.", "CWE-327"))
    if facts.get("sslv3"):
        issues.append((Severity.HIGH, "SSL 3.0 supported (POODLE)", "SSLv3 is vulnerable to POODLE.", "CWE-327"))
    if facts.get("tls1_0"):
        issues.append((Severity.MEDIUM, "TLS 1.0 supported (deprecated)", "TLS 1.0 is deprecated.", "CWE-327"))
    if facts.get("tls1_1"):
        issues.append((Severity.MEDIUM, "TLS 1.1 supported (deprecated)", "TLS 1.1 is deprecated.", "CWE-327"))
    if facts.get("expired"):
        issues.append((Severity.HIGH, "Certificate is expired", "The server certificate is past its validity period.", "CWE-298"))
    if facts.get("self_signed"):
        issues.append((Severity.MEDIUM, "Self-signed / untrusted certificate", "The certificate does not chain to a trusted CA.", "CWE-295"))
    if facts.get("hostname_mismatch"):
        issues.append((Severity.MEDIUM, "Certificate hostname mismatch", "The certificate is not valid for the requested hostname.", "CWE-297"))
    weak = facts.get("weak_ciphers") or []
    if weak:
        listed = ", ".join(sorted(set(weak))[:8])
        issues.append((Severity.MEDIUM, "Weak cipher suites supported", f"Weak ciphers offered: {listed}", "CWE-327"))
    return issues


def _gather_tls_facts(host: str, port: int) -> dict | None:
    """Run sslyze (blocking) and return a normalized facts dict, or None on error."""
    try:
        from sslyze import (
            ScanCommand,
            Scanner,
            ServerNetworkLocation,
            ServerScanRequest,
        )
    except Exception as exc:  # sslyze missing / import error
        logger.debug("sslyze unavailable: %s", exc)
        return None

    try:
        request = ServerScanRequest(
            server_location=ServerNetworkLocation(hostname=host, port=port),
            scan_commands={
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.CERTIFICATE_INFO,
            },
        )
        scanner = Scanner()
        scanner.queue_scans([request])
        for result in scanner.get_results():
            return _extract_facts(result)
    except Exception as exc:
        logger.debug("sslyze scan failed for %s:%s: %s", host, port, exc)
        return None
    return None


def _accepted(attempt) -> list:
    try:
        if attempt and getattr(attempt, "result", None):
            return list(attempt.result.accepted_cipher_suites)
    except Exception:
        pass
    return []


def _extract_facts(result) -> dict:
    facts: dict = {}
    try:
        sr = result.scan_result
    except Exception:
        return facts

    proto_map = {
        "sslv2": getattr(sr, "ssl_2_0_cipher_suites", None),
        "sslv3": getattr(sr, "ssl_3_0_cipher_suites", None),
        "tls1_0": getattr(sr, "tls_1_0_cipher_suites", None),
        "tls1_1": getattr(sr, "tls_1_1_cipher_suites", None),
    }
    weak: list[str] = []
    for key, attempt in proto_map.items():
        accepted = _accepted(attempt)
        facts[key] = bool(accepted)
        weak.extend(_weak_names(accepted))
    weak.extend(_weak_names(_accepted(getattr(sr, "tls_1_2_cipher_suites", None))))
    facts["weak_ciphers"] = sorted(set(weak))

    _extract_cert_facts(sr, facts, _hostname_of(result))
    return facts


def _weak_names(accepted: list) -> list[str]:
    names: list[str] = []
    for cs in accepted:
        try:
            name = cs.cipher_suite.name
        except Exception:
            continue
        if any(k in name for k in WEAK_CIPHER_KEYWORDS):
            names.append(name)
    return names


def _hostname_of(result) -> str | None:
    try:
        return result.server_location.hostname
    except Exception:
        return None


def _extract_cert_facts(sr, facts: dict, hostname: str | None) -> None:
    try:
        cert_attempt = getattr(sr, "certificate_info", None)
        cert_result = cert_attempt.result if cert_attempt else None
        deployment = cert_result.certificate_deployments[0] if cert_result else None
        if deployment is None:
            return
    except Exception:
        return

    try:
        validations = deployment.path_validation_results
        any_trusted = any(getattr(v, "was_validation_successful", False) for v in validations)
        facts["self_signed"] = not any_trusted
    except Exception:
        pass

    try:
        facts["hostname_mismatch"] = not deployment.leaf_certificate_subject_matches_hostname
    except Exception:
        pass

    try:
        leaf = deployment.received_certificate_chain[0]
        not_after = getattr(leaf, "not_valid_after_utc", None) or leaf.not_valid_after
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=UTC)
        facts["expired"] = not_after < datetime.now(UTC)
    except Exception:
        pass


@register
class TlsScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "tls"
    min_aggressiveness = Aggressiveness.PASSIVE

    def _https_target(self, ctx: ScanContext) -> tuple[str, int] | None:
        parts = urlsplit(ctx.config.target if "://" in ctx.config.target else f"//{ctx.config.target}")
        host = parts.hostname
        if not host:
            return None
        if parts.scheme == "https" or any(a.https_available for a in ctx.assets):
            return host, parts.port or 443
        return None

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        target = self._https_target(ctx)
        if target is None:
            return
        host, port = target
        if not ctx.scope.host_in_scope(host):
            logger.debug("tls: host %s not in scope; skipping", host)
            return

        facts = await asyncio.to_thread(_gather_tls_facts, host, port)
        if not facts:
            return

        url = f"https://{host}:{port}/"
        for severity, title, detail, cwe in classify_tls(facts):
            yield Finding(
                vuln_type="tls",
                title=title,
                severity=severity,
                confidence=Confidence.FIRM,
                url=url,
                description=detail,
                remediation=_REMEDIATION,
                cwe=cwe,
                scanner=SCANNER_NAME,
                evidence=Evidence(matched_at=f"{host}:{port}", notes=title),
            )


__all__ = ["TlsScanner", "classify_tls"]
