"""Cloud posture (CSPM/IAM) rules - turn a normalized inventory into Findings.

Read-only, offline analysis (the collection is what touches the provider; this
is pure). Each rule mirrors the ``iac`` analyzer's shape so cloud issues flow
into the existing report / attack-graph / runbook / notify pipeline unchanged.
Rules are conservative and high-signal: public storage, unencrypted data,
wildcard-admin IAM, principals without MFA, and internet-open sensitive ports.
The *combinations* that make these critical live in ``toxic``.
"""

from __future__ import annotations

from orthrus.cloud.models import CloudInventory, CloudResource
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity

# Ports that should essentially never be open to the whole internet.
SENSITIVE_PORTS: dict[int, str] = {
    22: "SSH", 23: "Telnet", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 1433: "MSSQL",
    5984: "CouchDB", 11211: "Memcached", 2375: "Docker API", 2379: "etcd",
}
_STORAGE = {"s3-bucket", "ebs-volume", "rds-instance", "rds-cluster", "dynamodb-table", "efs"}
_DB = {"rds-instance", "rds-cluster", "redshift-cluster", "elasticache", "documentdb"}
_PII_TAG_HINTS = ("pii", "sensitive", "confidential", "secret", "phi", "pci")


def _finding(
    title: str, severity: Severity, resource: CloudResource, desc: str, remediation: str,
    cwe: str, vuln_type: str, evidence: str = "",
) -> Finding:
    return Finding(
        vuln_type=vuln_type,
        title=title,
        severity=severity,
        confidence=Confidence.FIRM,
        url=resource.id,
        description=desc,
        remediation=remediation,
        cwe=cwe,
        scanner="cloud",
        evidence=Evidence(matched_at=resource.id, notes=(evidence or resource.label)[:200]),
    )


def _is_wildcard_admin(perms: list[str]) -> bool:
    return any(p.strip() in ("*", "*:*", "Allow:*") for p in perms)


def _has_sensitive_tag(resource: CloudResource) -> bool:
    blob = " ".join(f"{k}={v}" for k, v in resource.tags.items()).lower()
    return any(h in blob for h in _PII_TAG_HINTS)


def analyze_inventory(inventory: CloudInventory) -> list[Finding]:
    """Per-resource posture findings (no cross-resource correlation - see toxic)."""
    findings: list[Finding] = []
    for r in inventory.resources:
        # Public storage / buckets.
        if r.type == "s3-bucket" and r.public:
            sev = Severity.CRITICAL if _has_sensitive_tag(r) else Severity.HIGH
            findings.append(_finding(
                f"Public storage bucket '{r.label}'", sev, r,
                "The bucket is readable from the public internet; its contents are exposed to anyone.",
                "Enable Block Public Access, remove public ACLs/policies, serve via pre-signed URLs.",
                "CWE-284", "cloud-public-bucket",
                "public + sensitive tag" if sev == Severity.CRITICAL else "public",
            ))
        # Publicly reachable database.
        if r.type in _DB and r.public:
            findings.append(_finding(
                f"Publicly accessible database '{r.label}'", Severity.CRITICAL, r,
                "The database is reachable from the internet, exposing it to credential attacks and "
                "known-CVE exploitation.",
                "Set PubliclyAccessible=false; place it in a private subnet reachable only from the app tier.",
                "CWE-284", "cloud-public-db",
            ))
        # Unencrypted storage at rest.
        if r.type in _STORAGE and r.encrypted is False:
            findings.append(_finding(
                f"Encryption at rest disabled on '{r.label}'", Severity.MEDIUM, r,
                "Data is stored unencrypted; a disk/snapshot leak or misconfigured share discloses it.",
                "Enable at-rest encryption (SSE-KMS / storage-encrypted=true) and manage keys in KMS.",
                "CWE-311", "cloud-unencrypted",
            ))
        # IAM principal / policy with wildcard admin.
        if r.type in ("iam-user", "iam-role", "iam-policy", "iam-group") and _is_wildcard_admin(r.permissions):
            findings.append(_finding(
                f"Wildcard-admin permissions on '{r.label}'", Severity.HIGH, r,
                "The principal/policy grants Action:* (full administrative access) - it violates least "
                "privilege and massively widens blast radius on compromise.",
                "Replace '*' with the specific actions/resources required; use permission boundaries.",
                "CWE-269", "cloud-iam-admin", "permissions include '*'",
            ))
        # IAM user without MFA.
        if r.type == "iam-user" and r.mfa_enabled is False:
            findings.append(_finding(
                f"IAM user without MFA '{r.label}'", Severity.MEDIUM, r,
                "Console/API access is protected by a password/key alone; one phish or leak is full account access.",
                "Enforce MFA for all human users via an IAM policy condition (aws:MultiFactorAuthPresent).",
                "CWE-308", "cloud-no-mfa",
            ))
        # Sensitive port open to the world.
        world_ports = [p for p in r.open_ports if p in SENSITIVE_PORTS]
        if world_ports:
            names = ", ".join(f"{p}/{SENSITIVE_PORTS[p]}" for p in sorted(world_ports))
            findings.append(_finding(
                f"Sensitive port open to the internet on '{r.label}'", Severity.HIGH, r,
                f"Port(s) {names} are reachable from 0.0.0.0/0 - administrative/database services must "
                "never be world-exposed.",
                "Restrict the security-group ingress to specific trusted CIDRs / a bastion / VPN.",
                "CWE-284", "cloud-open-port", names,
            ))
    return findings


__all__ = ["analyze_inventory", "SENSITIVE_PORTS"]
