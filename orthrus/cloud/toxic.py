"""Toxic-combination analysis - the cloud "attack graph".

A single misconfiguration is often only medium risk; the danger is the
*combination*. An internet-reachable instance is fine until it carries an
admin role; an admin policy is fine until it's on a user without MFA. This
module correlates a resource's exposure with the privilege it can reach and
emits the few CRITICAL/HIGH *paths* an attacker would actually walk - the
cloud analogue of ``attack_graph``'s kill-chains. Each path is emitted as a
Finding referencing every resource in the chain, so it flows into the report,
runbook, and notify layers.

Pure and deterministic: ``toxic_combinations`` takes an inventory, returns
Findings.
"""

from __future__ import annotations

from orthrus.cloud.analyze import SENSITIVE_PORTS
from orthrus.cloud.models import CloudInventory, CloudResource
from orthrus.core.schemas import Confidence, Evidence, Finding, Severity

VULN_TYPE = "cloud-toxic-combo"
_COMPUTE = {"ec2-instance", "lambda", "lambda-function", "ecs-task", "ecs-service", "eks-node"}
_IAM_PRINCIPAL = {"iam-user", "iam-role", "iam-group"}
# Permission fragments that constitute meaningful privilege on compromise.
_PRIV_FRAGMENTS = ("*", "iam:", "s3:", "kms:", "secretsmanager:", "dynamodb:", "sts:assumerole")
_ESCALATION_ACTIONS = ("iam:passrole", "ec2:runinstances", "lambda:createfunction", "iam:createaccesskey")


def _combo(
    title: str, severity: Severity, primary: CloudResource, involved: list[CloudResource],
    desc: str, remediation: str, cwe: str,
) -> Finding:
    arns = " → ".join(r.id for r in involved)
    return Finding(
        vuln_type=VULN_TYPE,
        title=title,
        severity=severity,
        confidence=Confidence.FIRM,
        url=primary.id,
        description=f"{desc}\n\nChain: {arns}",
        remediation=remediation,
        cwe=cwe,
        scanner="cloud",
        evidence=Evidence(matched_at=primary.id, notes=f"resources: {arns}"[:200]),
    )


def _privileged(perms: list[str]) -> bool:
    low = [p.lower() for p in perms]
    if any(p in ("*", "*:*") for p in low):
        return True
    return any(frag in p for p in low for frag in _PRIV_FRAGMENTS if frag != "*")


def _resolve_roles(refs: list[str], roles: list[CloudResource]) -> list[CloudResource]:
    out: list[CloudResource] = []
    for ref in refs:
        match = next(
            (r for r in roles if r.id == ref or r.name == ref or (ref and (ref in r.id or ref in r.name))),
            None,
        )
        if match and match not in out:
            out.append(match)
    return out


def toxic_combinations(inventory: CloudInventory) -> list[Finding]:
    findings: list[Finding] = []
    roles = [r for r in inventory.resources if r.type in ("iam-role", "iam-instance-profile", "iam-policy")]

    # T1 - internet-reachable compute carrying a privileged role.
    for c in inventory.resources:
        if c.type not in _COMPUTE:
            continue
        open_admin = sorted(p for p in c.open_ports if p in SENSITIVE_PORTS)
        exposed = c.public or bool(open_admin)
        if not exposed:
            continue
        priv_roles = [r for r in _resolve_roles(c.attached_roles, roles) if _privileged(r.permissions)]
        if not priv_roles:
            continue
        how = "a public endpoint" if c.public else f"world-open port(s) {', '.join(map(str, open_admin))}"
        findings.append(_combo(
            f"Internet-reachable workload with a privileged role '{c.label}'", Severity.CRITICAL,
            c, [c, *priv_roles],
            f"'{c.label}' is reachable from the internet ({how}) and carries a role with broad "
            "privileges. Compromising the workload (RCE, SSRF to the metadata service, a dependency "
            "CVE) yields those cloud permissions directly - request forgery becomes account compromise.",
            "Remove the privileged role or scope it to least privilege; enforce IMDSv2; take the "
            "workload off the public internet (private subnet + load balancer / bastion).",
            "CWE-269",
        ))

    # T4 - full-admin human user without MFA.
    for u in inventory.by_type("iam-user"):
        if u.mfa_enabled is False and _privileged(u.permissions):
            findings.append(_combo(
                f"Privileged IAM user without MFA '{u.label}'", Severity.CRITICAL, u, [u],
                "This human user holds broad/admin permissions but has no MFA. A single credential "
                "phish or leak is a full account takeover with nothing else in the way.",
                "Enforce MFA (deny all actions when aws:MultiFactorAuthPresent is false) and reduce the "
                "user's permissions to least privilege.",
                "CWE-308",
            ))

    # T5 - privilege-escalation permission combination (PassRole + create).
    for p in inventory.resources:
        if p.type not in _IAM_PRINCIPAL and p.type != "iam-policy":
            continue
        low = [a.lower() for a in p.permissions]
        # A bare "*" is already flagged as wildcard-admin by posture - T5 targets the
        # non-obvious escalation combo (explicit PassRole + an explicit create action).
        has_pass = any("iam:passrole" in a or a == "iam:*" for a in low)
        has_create = any(
            act in a for a in low for act in _ESCALATION_ACTIONS if act != "iam:passrole"
        ) or any(a in ("ec2:*", "lambda:*") for a in low)
        if has_pass and has_create:
            findings.append(_combo(
                f"IAM privilege-escalation path on '{p.label}'", Severity.HIGH, p, [p],
                "The principal can both pass an IAM role and create a compute resource (or holds '*'). "
                "That combination lets it pass a more-privileged role to a new instance/function and "
                "escalate to that role - a classic IAM privilege-escalation primitive.",
                "Separate iam:PassRole from resource-creation permissions; constrain PassRole to "
                "specific low-privilege roles via a resource condition.",
                "CWE-269",
            ))
    return findings


def analyze_cloud(inventory: CloudInventory) -> list[Finding]:
    """Full cloud analysis: toxic combinations first (worst), then posture findings."""
    from orthrus.cloud.analyze import analyze_inventory

    return toxic_combinations(inventory) + analyze_inventory(inventory)


__all__ = ["toxic_combinations", "analyze_cloud", "VULN_TYPE"]
