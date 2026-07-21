"""Provider-normalized cloud inventory - the input to CSPM/IAM posture analysis.

A cloud "snapshot" is deliberately provider-agnostic and flat: a list of
``CloudResource`` records with the handful of attributes posture rules and the
toxic-combination graph actually reason over (public exposure, encryption, IAM
permissions, attached roles, internet-open ports, tags). It can be produced by
the read-only ``collect`` adapter (boto3) or hand-exported from `aws`/Steampipe/
ScoutSuite and fed to ``orthrus cloud`` as JSON - so analysis never needs live
credentials to run or to be tested.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def _as_str_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return []


def _as_int_list(value: Any) -> list[int]:
    out: list[int] = []
    for v in value if isinstance(value, (list, tuple)) else []:
        try:
            out.append(int(v))
        except (TypeError, ValueError):
            continue
    return out


@dataclass
class CloudResource:
    """One cloud resource, normalized to the attributes posture rules need."""

    id: str  # ARN / resource id - used as the finding URL
    type: str  # e.g. "s3-bucket", "ec2-instance", "iam-user", "iam-role", "security-group", "rds-instance"
    name: str = ""
    region: str | None = None
    public: bool = False  # internet-exposed (public IP / public ACL / publicly accessible)
    encrypted: bool | None = None  # at-rest encryption; None = unknown/NA
    mfa_enabled: bool | None = None  # for IAM principals
    permissions: list[str] = field(default_factory=list)  # granted IAM actions, e.g. ["s3:*", "*"]
    attached_roles: list[str] = field(default_factory=list)  # role/instance-profile ids on compute
    open_ports: list[int] = field(default_factory=list)  # ports reachable from 0.0.0.0/0
    tags: dict[str, str] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> CloudResource:
        return cls(
            id=str(data.get("id") or data.get("arn") or data.get("name") or "unknown"),
            type=str(data.get("type") or "resource"),
            name=str(data.get("name") or ""),
            region=data.get("region"),
            public=bool(data.get("public", False)),
            encrypted=data.get("encrypted"),
            mfa_enabled=data.get("mfa_enabled"),
            permissions=_as_str_list(data.get("permissions")),
            attached_roles=_as_str_list(data.get("attached_roles")),
            open_ports=_as_int_list(data.get("open_ports")),
            tags={str(k): str(v) for k, v in (data.get("tags") or {}).items()},
            extra=dict(data.get("extra") or {}),
        )

    @property
    def label(self) -> str:
        return self.name or self.id


@dataclass
class CloudInventory:
    """A collected/imported set of cloud resources for one account."""

    provider: str = "aws"
    account_id: str = ""
    resources: list[CloudResource] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> CloudInventory:
        raw = data.get("resources")
        resources = [CloudResource.from_dict(r) for r in raw if isinstance(r, dict)] if isinstance(raw, list) else []
        return cls(
            provider=str(data.get("provider") or "aws"),
            account_id=str(data.get("account_id") or ""),
            resources=resources,
        )

    def by_type(self, *types: str) -> list[CloudResource]:
        want = set(types)
        return [r for r in self.resources if r.type in want]

    def get(self, resource_id: str) -> CloudResource | None:
        return next((r for r in self.resources if r.id == resource_id), None)


__all__ = ["CloudResource", "CloudInventory"]
