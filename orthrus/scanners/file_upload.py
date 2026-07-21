"""Unrestricted file-upload scanner.

Attempts to upload a file with a dangerous (server-executable / active) type to
endpoints that look like upload handlers, and flags those that accept it. An
accepted ``.php``/``.svg``/``.html`` upload is a common path to RCE (web shell)
or stored XSS.

This probe is **mutating** (it creates a resource), so it only runs under
``--aggressive`` and uploads a clearly-benign, inert marker file - never an
actual web shell payload.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.file-upload")

SCANNER_NAME = "file-upload"
MAX_ENDPOINTS = 15

# Path/param hints that mark an upload handler.
_UPLOAD_HINTS = (
    "upload", "avatar", "attachment", "import", "media",
    "/photo", "/image", "/document", "/file", "profilepic",
)

# Benign, inert marker - NOT a working web shell. The filename/extension is the
# dangerous part being tested; the content is harmless.
_MARKER = "ORTHRUS_UPLOAD_OK"
_DANGEROUS_FILES = (
    ("orthrus_test.php", b"<!-- " + _MARKER.encode() + b" -->", "image/png"),
    ("orthrus_test.svg", b"<svg xmlns='http://www.w3.org/2000/svg'><!--" + _MARKER.encode() + b"--></svg>", "image/svg+xml"),
    ("orthrus_test.html", b"<!-- " + _MARKER.encode() + b" -->", "image/jpeg"),
)

_REJECTION_TOKENS = (
    "not allowed", "invalid", "forbidden", "unsupported", "only ", "must be",
    "rejected", "error", "denied", "not permitted", "bad request",
)


def is_upload_endpoint(url: str, param_names: tuple[str, ...] = ()) -> bool:
    low = url.lower()
    if any(h in low for h in _UPLOAD_HINTS):
        return True
    return any(h.strip("/") in p.lower() for p in param_names for h in _UPLOAD_HINTS)


def upload_accepted(status: int, body: str, filename: str) -> bool:
    """True if a dangerous-typed upload looks accepted (not rejected)."""
    if not (200 <= status < 300):
        return False
    low = body.lower()
    if any(tok in low for tok in _REJECTION_TOKENS):
        return False
    # Accepted if the dangerous filename/extension is echoed back, or an explicit
    # success marker is present.
    ext = filename.rsplit(".", 1)[-1].lower()
    return filename.lower() in low or f".{ext}" in low or any(
        s in low for s in ("uploaded", "success", "stored", "saved", "/uploads/")
    )


@register
class FileUploadScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "file-upload"
    min_aggressiveness = Aggressiveness.AGGRESSIVE  # mutating: creates a resource

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        tested = 0
        for ep in ctx.endpoints:
            url = ep.url.split("#", 1)[0]
            params = tuple(p.name for p in getattr(ep, "params", []))
            if url in seen or not is_upload_endpoint(url, params):
                continue
            if not ctx.scope.is_allowed(url):
                continue
            seen.add(url)
            if tested >= MAX_ENDPOINTS:
                break
            tested += 1

            finding = await self._probe(ctx, url)
            if finding is not None:
                yield finding

    async def _probe(self, ctx: ScanContext, url: str) -> Finding | None:
        for filename, content, ctype in _DANGEROUS_FILES:
            try:
                resp = await ctx.http.post(
                    url, files={"file": (filename, content, ctype)}, follow_redirects=True
                )
            except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
                logger.debug("file-upload probe failed for %s: %s", url, exc)
                continue
            if upload_accepted(resp.status_code, resp.text, filename):
                return self._finding(url, filename)
        return None

    def _finding(self, url: str, filename: str) -> Finding:
        path = urlsplit(url).path
        ext = filename.rsplit(".", 1)[-1]
        return Finding(
            vuln_type="file-upload",
            title=f"Unrestricted file upload (.{ext} accepted) at {path}",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            url=url,
            description=(
                f"The upload endpoint {path} accepted a file with a dangerous '.{ext}' extension. "
                "If uploaded files are served from the web root or interpreted by the server, an "
                "attacker can upload a web shell (RCE) or a .svg/.html for stored XSS. The probe "
                "uploaded a harmless inert marker, not a working payload - confirm where the file "
                "lands and whether it executes."
            ),
            remediation=(
                "Validate uploads by content (magic bytes) and an allow-list of extensions/MIME "
                "types; store outside the web root with a generated name; serve via a handler that "
                "forces a non-executable Content-Type and Content-Disposition: attachment."
            ),
            cwe="CWE-434",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                request_raw=f"multipart upload: {filename}",
                notes="dangerous-typed file accepted without rejection",
            ),
        )


__all__ = ["FileUploadScanner", "is_upload_endpoint", "upload_accepted"]
