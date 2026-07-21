"""Automated remediation patch generation.

Turns findings into concrete, paste-able fixes - config/code snippets keyed by
vulnerability type - so the runbook's *what to do* becomes *here is the change*.
The template library is deterministic and unit-tested; an optional LLM pass
(`llm_patch`, same opt-in/best-effort shape as triage's judge) can produce a
context-specific patch for a finding when a template doesn't fit.

Patches are grouped by fix (like the runbook) and rendered to Markdown with
fenced code blocks, or emitted as JSON. Pure and deterministic: ``build_patch_report``
takes findings and returns a ``PatchReport``.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from orthrus.triage import DEFAULT_MODEL

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Collapse scanner-specific vuln types onto a canonical remediation key.
_ALIASES = {
    "reflected-xss": "xss", "dom-xss": "xss", "stored-xss": "xss", "xss-reflected": "xss",
    "auth-session": "cookie", "cookie-session": "cookie", "session": "cookie",
    "insecure-cookie": "cookie",
    "csp-weakness": "csp", "clickjacking": "security-headers", "x-frame-options": "security-headers",
    "command-injection": "cmd-injection", "os-command-injection": "cmd-injection",
    "path-traversal": "lfi", "file-read": "lfi",
    "broken-authorization": "idor", "bola": "idor", "bfla": "idor",
    "tls-analysis": "tls", "weak-tls": "tls",
}


@dataclass
class Patch:
    """One concrete remediation snippet."""

    title: str
    language: str  # code-fence language: nginx, python, javascript, hcl, http, ...
    body: str
    platform: str = ""  # nginx / express / django / terraform / ...

    def to_dict(self) -> dict:
        return {"title": self.title, "language": self.language, "body": self.body, "platform": self.platform}


def _p(title: str, language: str, body: str, platform: str = "") -> Patch:
    return Patch(title=title, language=language, body=body.strip(), platform=platform)


# --- the template library ------------------------------------------------

PATCH_LIBRARY: dict[str, list[Patch]] = {
    "security-headers": [
        _p("Add security response headers", "nginx", """
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'" always;
""", "nginx"),
        _p("Add security headers (Express/helmet)", "javascript", """
const helmet = require("helmet");
app.use(helmet());                       // HSTS, X-Frame-Options, nosniff, etc.
app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: ["'self'"] } }));
""", "express"),
    ],
    "csp": [
        _p("Start from a strict, nonce-based CSP", "http", """
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{RANDOM}';
  object-src 'none'; base-uri 'none'; frame-ancestors 'none'
""", ""),
    ],
    "cors": [
        _p("Reflect only an allow-listed origin (never '*') with credentials", "javascript", """
const ALLOWED = new Set(["https://app.example.com"]);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOWED.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);   // echo a vetted origin only
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  next();
});
""", "express"),
    ],
    "cookie": [
        _p("Set Secure, HttpOnly and SameSite on session cookies", "http", """
Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax; Path=/
""", ""),
        _p("Express session cookie flags", "javascript", """
app.use(session({
  cookie: { secure: true, httpOnly: true, sameSite: "lax" },
}));
""", "express"),
    ],
    "sqli": [
        _p("Use parameterized queries (never string-format SQL)", "python", """
-# vulnerable: user input concatenated into SQL
-cur.execute("SELECT * FROM users WHERE email = '" + email + "'")
+# fixed: bound parameter - the driver escapes it
+cur.execute("SELECT * FROM users WHERE email = %s", (email,))
""", "python"),
        _p("Parameterized query (Node / pg)", "javascript", """
-const r = await pool.query(`SELECT * FROM users WHERE id = ${id}`);
+const r = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
""", "node"),
    ],
    "xss": [
        _p("Contextually encode output; sanitize any raw HTML sink", "javascript", """
-el.innerHTML = userInput;                         // sink executes injected markup
+el.textContent = userInput;                       // text, never parsed as HTML
+// when HTML is genuinely required:
+import DOMPurify from "dompurify";
+el.innerHTML = DOMPurify.sanitize(userInput);
""", ""),
        _p("Defense in depth: a CSP that blocks inline script", "http", """
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
""", ""),
    ],
    "open-redirect": [
        _p("Allow-list redirect destinations", "python", """
from urllib.parse import urlparse
ALLOWED_HOSTS = {"app.example.com"}
def safe_redirect_target(target: str, default: str = "/") -> str:
    u = urlparse(target)
    if not u.netloc and target.startswith("/"):   # relative path, ok
        return target
    return target if u.netloc in ALLOWED_HOSTS else default
""", ""),
    ],
    "ssrf": [
        _p("Allow-list outbound hosts; block link-local / metadata", "python", """
import ipaddress, socket
ALLOWED = {"api.partner.com"}
def guard(url_host: str) -> None:
    if url_host not in ALLOWED:
        raise ValueError("host not allow-listed")
    ip = ipaddress.ip_address(socket.gethostbyname(url_host))
    if ip.is_private or ip.is_loopback or ip.is_link_local:  # 169.254.169.254, 127.0.0.0/8, ...
        raise ValueError("blocked internal address")
""", ""),
    ],
    "lfi": [
        _p("Canonicalize and confine paths to a base directory", "python", """
import os
BASE = "/srv/app/data"
def safe_path(name: str) -> str:
    full = os.path.realpath(os.path.join(BASE, name))
    if not full.startswith(BASE + os.sep):        # rejects ../ traversal
        raise ValueError("path escapes base directory")
    return full
""", ""),
    ],
    "cmd-injection": [
        _p("Never invoke a shell; pass an argv array", "python", """
-import os
-os.system("ping -c 1 " + host)                    # shell metachars → injection
+import subprocess
+subprocess.run(["ping", "-c", "1", host], shell=False, check=True)
""", ""),
    ],
    "idor": [
        _p("Enforce ownership on every object access (server-side)", "python", """
-order = Order.get(order_id)                        # trusts the id from the client
+order = Order.get(order_id)
+if order.owner_id != current_user.id and not current_user.is_admin:
+    abort(403)                                     # authorize, don't just authenticate
""", ""),
    ],
    "csrf": [
        _p("Require an anti-CSRF token + SameSite cookies", "python", """
# Flask-WTF / Django both ship CSRF middleware - enable it and render the token:
# <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
# and set the session cookie SameSite=Lax so cross-site POSTs drop the cookie.
""", ""),
    ],
    "tls": [
        _p("Disable legacy protocols and weak ciphers", "nginx", """
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384;
""", "nginx"),
    ],
    "xxe": [
        _p("Disable external entities / DTDs in the XML parser", "python", """
-import xml.etree.ElementTree as ET               # or lxml with default resolver
-tree = ET.parse(untrusted)
+from lxml import etree
+parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False)
+tree = etree.parse(untrusted, parser)
""", ""),
    ],
    "cloud-public-bucket": [
        _p("Block all public access on the bucket", "hcl", """
resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
""", "terraform"),
    ],
    "cloud-unencrypted": [
        _p("Enforce at-rest encryption (SSE-KMS)", "hcl", """
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule { apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" } }
}
""", "terraform"),
    ],
    "cloud-open-port": [
        _p("Restrict the security-group ingress to trusted CIDRs", "hcl", """
resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]          # a bastion/VPN range - never 0.0.0.0/0
  security_group_id = aws_security_group.this.id
}
""", "terraform"),
    ],
}


def normalize_vuln_type(vuln_type: str) -> str:
    return _ALIASES.get(vuln_type, vuln_type)


def patches_for(vuln_type: str) -> list[Patch]:
    """Templated patches applicable to a vuln type (empty if none)."""
    return PATCH_LIBRARY.get(normalize_vuln_type(vuln_type), [])


# --- grouping + rendering ------------------------------------------------

def _sev(f: object) -> str:
    s = getattr(f, "severity", "info")
    return getattr(s, "value", s) or "info"


def _worst(sevs: list[str]) -> str:
    rank = max((_SEV_ORDER.get(s, 0) for s in sevs), default=0)
    return next((k for k, v in _SEV_ORDER.items() if v == rank), "info")


def _fullest(values: list[str]) -> str:
    return max((v for v in values if v), key=len, default="")


@dataclass
class PatchGroup:
    vuln_type: str
    title: str
    severity: str
    count: int
    urls: list[str]
    remediation: str
    patches: list[Patch] = field(default_factory=list)

    @property
    def has_patch(self) -> bool:
        return bool(self.patches)

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type, "title": self.title, "severity": self.severity,
            "count": self.count, "endpoints": len(self.urls), "urls": self.urls,
            "remediation": self.remediation, "patches": [p.to_dict() for p in self.patches],
        }


@dataclass
class PatchReport:
    groups: list[PatchGroup]
    total_findings: int
    target: str | None = None
    scan_id: str | None = None

    @property
    def patched(self) -> int:
        return sum(1 for g in self.groups if g.has_patch)

    def summary(self) -> str:
        if not self.groups:
            return f"no remediable findings ({self.total_findings} findings)"
        return (
            f"{self.total_findings} finding(s) → {len(self.groups)} fix type(s); "
            f"{self.patched} with a concrete patch"
        )

    def to_markdown(self) -> str:
        scope = self.target or self.scan_id or "scan"
        out: list[str] = [f"# Remediation Patches - {scope}", "", f"_{self.summary()}._", ""]
        if not self.groups:
            return "\n".join([*out, "No findings require remediation."]) + "\n"
        for i, g in enumerate(self.groups, 1):
            out.append(f"## {i}. {g.title} (`{g.vuln_type}`) - {g.severity.upper()}")
            out.append(f"Affects {g.count} finding(s) across {len(g.urls)} endpoint(s).")
            if g.remediation:
                out += ["", f"> {g.remediation}"]
            if not g.patches:
                out += ["", "_No templated patch for this type yet - apply the remediation above._", ""]
                continue
            for patch in g.patches:
                label = f"{patch.title}" + (f" · {patch.platform}" if patch.platform else "")
                out += ["", f"### {label}", "", f"```{patch.language}", patch.body, "```"]
            out.append("")
        return "\n".join(out) + "\n"

    def to_dict(self) -> dict:
        return {
            "summary": self.summary(), "total_findings": self.total_findings,
            "fix_types": len(self.groups), "patched": self.patched,
            "groups": [g.to_dict() for g in self.groups],
        }


def build_patch_report(
    findings: list, *, target: str | None = None, scan_id: str | None = None
) -> PatchReport:
    """Group findings by fix and attach templated patches, patched types first."""
    groups: dict[str, list] = {}
    for f in findings:
        groups.setdefault(normalize_vuln_type(getattr(f, "vuln_type", "") or "finding"), []).append(f)

    out: list[PatchGroup] = []
    for vt, members in groups.items():
        titles = [getattr(m, "title", "") for m in members if getattr(m, "title", "")]
        title = Counter(titles).most_common(1)[0][0] if titles else vt
        out.append(PatchGroup(
            vuln_type=vt,
            title=title,
            severity=_worst([_sev(m) for m in members]),
            count=len(members),
            urls=sorted({getattr(m, "url", "") or "" for m in members}),
            remediation=_fullest([getattr(m, "remediation", "") or "" for m in members]),
            patches=patches_for(vt),
        ))
    # Patched types first, then by severity, then blast radius.
    out.sort(key=lambda g: (0 if g.has_patch else 1, -_SEV_ORDER.get(g.severity, 0), -g.count, g.vuln_type))
    return PatchReport(out, total_findings=len(findings), target=target, scan_id=scan_id)


# --- optional LLM enrichment (opt-in, best-effort) -----------------------

_CODE_FENCE = re.compile(r"```(\w+)?\n(.*?)```", re.S)


def build_patch_prompt(finding: object) -> str:
    return (
        "You are an application-security engineer. Produce a MINIMAL, secure code or "
        "configuration patch that fixes the following finding. Respond with a single "
        "fenced code block (```lang ... ```), no prose.\n\n"
        f"Type: {getattr(finding, 'vuln_type', '')}\n"
        f"Title: {getattr(finding, 'title', '')}\n"
        f"URL/location: {getattr(finding, 'url', '')}\n"
        f"Parameter: {getattr(finding, 'parameter', '') or '-'}\n"
        f"Existing remediation note: {getattr(finding, 'remediation', '') or '-'}"
    )


def parse_patch_response(text: str) -> Patch | None:
    """Extract the first fenced code block from an LLM reply into a Patch."""
    m = _CODE_FENCE.search(text or "")
    if not m:
        return None
    return _p("AI-suggested patch", m.group(1) or "text", m.group(2), platform="ai")


async def llm_patch(finding: object, api_key: str, *, model: str = DEFAULT_MODEL) -> Patch | None:
    """Ask an Anthropic model for a context-specific patch. Best-effort → None on error."""
    import httpx

    from orthrus.triage import ANTHROPIC_URL

    payload = {"model": model, "max_tokens": 700,
               "messages": [{"role": "user", "content": build_patch_prompt(finding)}]}
    headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(ANTHROPIC_URL, json=payload, headers=headers)
        if resp.status_code != 200:
            return None
        blocks = resp.json().get("content", [])
        return parse_patch_response("".join(b.get("text", "") for b in blocks if b.get("type") == "text"))
    except Exception:
        return None


__all__ = [
    "Patch", "PatchGroup", "PatchReport",
    "PATCH_LIBRARY", "patches_for", "normalize_vuln_type",
    "build_patch_report", "build_patch_prompt", "parse_patch_response", "llm_patch",
]
