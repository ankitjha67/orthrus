"""Infrastructure-as-Code misconfiguration analyzer — native, offline, no deps
beyond PyYAML (already required).

Parses Dockerfiles, docker-compose, and Terraform and emits ORTHRUS ``Finding``s
for high-signal misconfigurations (root containers, unpinned/secret-bearing
images, privileged/socket-mounted services, world-open security groups, public
buckets, unencrypted storage, hardcoded secrets). Driven by ``orthrus iac PATH``.

Detection is conservative (literal/structural patterns, value-shape guards) to
keep false positives low; findings are FIRM but worth human review.
"""

from __future__ import annotations

import os
import re

import yaml

from orthrus.core.schemas import Confidence, Evidence, Finding, Severity

VULN_TYPE = "iac-misconfig"
_SECRET_KEY = re.compile(r"(pass(word)?|secret|api[_-]?key|access[_-]?key|private[_-]?key|token)", re.I)
_SKIP_DIRS = {".git", ".hg", "node_modules", ".venv", "venv", "__pycache__", ".terraform"}


def _is_secret_value(value: str) -> bool:
    """A literal secret, not a reference (path, $VAR, ${...}, empty)."""
    v = value.strip().strip('"').strip("'")
    return bool(v) and not v.startswith(("/", "$", "{{"))


def _finding(
    title: str, severity: Severity, path: str, line: int, desc: str, remediation: str, cwe: str, evidence: str
) -> Finding:
    loc = f"{path}:{line}" if line else path
    return Finding(
        vuln_type=VULN_TYPE,
        title=title,
        severity=severity,
        confidence=Confidence.FIRM,
        url=loc,
        description=desc,
        remediation=remediation,
        cwe=cwe,
        scanner="iac",
        evidence=Evidence(matched_at=loc, notes=evidence[:200]),
    )


def analyze_dockerfile(text: str, path: str = "Dockerfile") -> list[Finding]:
    findings: list[Finding] = []
    saw_user = False
    user_is_root = True
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        low = line.lower()
        if low.startswith("from "):
            image = line.split(None, 1)[1].split(" as ")[0].split(" AS ")[0].strip()
            last = image.split("/")[-1]
            tag = last.rsplit(":", 1)[1] if ":" in last else ""
            if "@sha256:" not in image and (not tag or tag == "latest"):
                findings.append(_finding(
                    "Unpinned base image (no immutable tag/digest)", Severity.MEDIUM, path, i,
                    "The base image isn't pinned, so builds are non-reproducible and may pull a "
                    "changed or compromised layer.",
                    "Pin to a version and digest: FROM image:1.2.3@sha256:...", "CWE-1104", line,
                ))
        elif low.startswith("user "):
            saw_user = True
            user_is_root = line.split(None, 1)[1].strip().strip('"').strip("'") in ("root", "0")
        if re.search(r"\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash)\b", low):
            findings.append(_finding(
                "Remote script piped into a shell (curl|sh)", Severity.MEDIUM, path, i,
                "Piping a downloaded script straight into a shell runs unverified remote code at "
                "build time (supply-chain risk).",
                "Download to a file, verify a checksum/signature, then execute.", "CWE-494", line,
            ))
        if re.search(r"^\s*add\s+https?://", low):
            findings.append(_finding(
                "ADD from a remote URL", Severity.LOW, path, i,
                "ADD <url> fetches over the network with no integrity check.",
                "Use COPY for local files; for remote, download + verify + RUN explicitly.",
                "CWE-494", line,
            ))
        env = re.match(r"(?:env|arg)\s+([^\s=]+)\s*[= ]\s*(.+)", line, re.IGNORECASE)
        if env and _SECRET_KEY.search(env.group(1)) and _is_secret_value(env.group(2)):
            findings.append(_finding(
                f"Hardcoded secret baked into the image ({env.group(1)})", Severity.HIGH, path, i,
                "A secret-looking ENV/ARG with a literal value is stored in the image and "
                "recoverable from any layer.",
                "Inject secrets at runtime (env vars, secret mounts, a secret manager) — never bake "
                "them into the image.", "CWE-798", f"{env.group(1)}=***",
            ))
    if not saw_user or user_is_root:
        findings.append(_finding(
            "Container runs as root (no non-root USER)", Severity.HIGH, path, 0,
            "No non-root USER is set, so the main process runs as root; a container escape then has "
            "root in the host namespace.",
            "Create and switch to an unprivileged user (USER appuser).", "CWE-250",
            "no USER directive / USER root",
        ))
    return findings


def _env_items(env: object) -> list[tuple[str, str]]:
    if isinstance(env, dict):
        return [(str(k), str(v)) for k, v in env.items()]
    if isinstance(env, list):
        out = []
        for item in env:
            if isinstance(item, str) and "=" in item:
                k, _, v = item.partition("=")
                out.append((k, v))
        return out
    return []


def analyze_compose(text: str, path: str = "docker-compose.yml") -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return findings
    if not isinstance(data, dict):
        return findings
    services = data.get("services")
    if not isinstance(services, dict):
        return findings
    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        loc = f"{path} (service: {name})"
        if svc.get("privileged") is True:
            findings.append(_finding(
                f"Privileged container '{name}'", Severity.HIGH, path, 0,
                "privileged: true grants ~all host capabilities — a compromise is a trivial host "
                "takeover.",
                "Remove privileged; add only the specific capabilities required.", "CWE-250", loc,
            ))
        if svc.get("network_mode") == "host":
            findings.append(_finding(
                f"Host network mode '{name}'", Severity.MEDIUM, path, 0,
                "network_mode: host removes network isolation; the container shares the host stack.",
                "Use bridge networking and publish only required ports.", "CWE-668", loc,
            ))
        if str(svc.get("pid", "")) == "host":
            findings.append(_finding(
                f"Host PID namespace '{name}'", Severity.MEDIUM, path, 0,
                "pid: host lets the container see and signal host processes.",
                "Remove pid: host.", "CWE-668", loc,
            ))
        if any("/var/run/docker.sock" in str(v) for v in (svc.get("volumes") or [])):
            findings.append(_finding(
                f"Docker socket mounted into '{name}'", Severity.HIGH, path, 0,
                "Mounting /var/run/docker.sock grants control of the Docker daemon = root on the host.",
                "Don't mount the docker socket; use a scoped, authenticated API/proxy if needed.",
                "CWE-668", loc,
            ))
        if any(str(c).upper() in ("ALL", "SYS_ADMIN", "NET_ADMIN") for c in (svc.get("cap_add") or [])):
            findings.append(_finding(
                f"Dangerous Linux capability added to '{name}'", Severity.HIGH, path, 0,
                "cap_add includes a powerful capability (ALL/SYS_ADMIN) that enables container escape.",
                "cap_drop: [ALL] and add only the minimal capabilities required.", "CWE-250", loc,
            ))
        image = str(svc.get("image", ""))
        if image and "@sha256:" not in image and (":" not in image.split("/")[-1] or image.endswith(":latest")):
            findings.append(_finding(
                f"Unpinned image in '{name}'", Severity.LOW, path, 0,
                "The image isn't pinned to an immutable tag/digest.",
                "Pin to a version and digest.", "CWE-1104", f"{loc} image={image}",
            ))
        for key, value in _env_items(svc.get("environment")):
            if _SECRET_KEY.search(key) and _is_secret_value(value):
                findings.append(_finding(
                    f"Hardcoded secret in '{name}' environment ({key})", Severity.HIGH, path, 0,
                    "A secret-looking environment value is committed in the compose file.",
                    "Use Docker secrets or a secret manager; reference via ${ENV_VAR}.", "CWE-798", loc,
                ))
                break
    return findings


def analyze_terraform(text: str, path: str = "main.tf") -> list[Finding]:
    findings: list[Finding] = []
    for i, raw in enumerate(text.splitlines(), 1):
        low = raw.lower()
        if "0.0.0.0/0" in raw and ("cidr" in low or "ingress" in low):
            findings.append(_finding(
                "Security group open to the internet (0.0.0.0/0)", Severity.HIGH, path, i,
                "An ingress rule allows 0.0.0.0/0 — the resource is reachable from the entire internet.",
                "Restrict cidr_blocks to specific trusted ranges.", "CWE-284", raw.strip(),
            ))
        if re.search(r'acl\s*=\s*"public-read', low):
            findings.append(_finding(
                "Public storage ACL (public-read/-write)", Severity.HIGH, path, i,
                "A public-read(-write) ACL exposes object storage contents to anyone.",
                "Set acl=private and use bucket policies / pre-signed URLs.", "CWE-284", raw.strip(),
            ))
        if re.search(r"encrypted\s*=\s*false", low):
            findings.append(_finding(
                "Encryption at rest disabled (encrypted=false)", Severity.MEDIUM, path, i,
                "Encryption at rest is explicitly turned off.",
                "Set encrypted=true and manage keys via KMS.", "CWE-311", raw.strip(),
            ))
        secret = re.search(
            r'\b(password|secret|secret_key|access_key|private_key|token)\s*=\s*"([^"]+)"', low
        )
        if secret and "var." not in raw and not secret.group(2).startswith("${"):
            findings.append(_finding(
                f"Hardcoded secret in Terraform ({secret.group(1)})", Severity.HIGH, path, i,
                "A secret is committed as a literal in the .tf source (and ends up in state).",
                "Use input variables + a secrets backend (Vault/SSM/env); never commit literals.",
                "CWE-798", f"{secret.group(1)} = ***",
            ))
    return findings


def _dispatch(name: str) -> str | None:
    low = name.lower()
    if "dockerfile" in low:
        return "docker"
    if low.endswith(".tf"):
        return "terraform"
    if ("compose" in low) and low.endswith((".yml", ".yaml")):
        return "compose"
    return None


def analyze_file(path: str) -> list[Finding]:
    kind = _dispatch(os.path.basename(path))
    if kind is None:
        return []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
    except OSError:
        return []
    if kind == "docker":
        return analyze_dockerfile(text, path)
    if kind == "terraform":
        return analyze_terraform(text, path)
    return analyze_compose(text, path)


def analyze_path(path: str) -> list[Finding]:
    """Analyze a single IaC file or recursively walk a directory."""
    if os.path.isfile(path):
        return analyze_file(path)
    findings: list[Finding] = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in files:
            if _dispatch(fname):
                findings.extend(analyze_file(os.path.join(root, fname)))
    return findings


__all__ = [
    "analyze_path",
    "analyze_file",
    "analyze_dockerfile",
    "analyze_compose",
    "analyze_terraform",
    "VULN_TYPE",
]
