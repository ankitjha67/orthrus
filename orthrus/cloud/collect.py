"""Read-only AWS collection → normalized ``CloudInventory``.

This is the only part of the cloud subsystem that talks to a provider, and it is
strictly **read-only** (list/describe/get) using the operator's own credentials
against their own account — the same posture-assessment model as Prowler /
ScoutSuite. It never creates, modifies, or deletes anything. boto3 is imported
lazily (optional ``[cloud]`` extra); a ``client_factory`` can be injected so the
normalization is unit-tested without live credentials.

Collection is best-effort: a failure for one service/region is logged and
skipped so a partial inventory is still useful. Exact IAM action expansion is
intentionally approximate (attached AdministratorAccess ⇒ ``["*"]``) — enough
for posture/toxic rules without walking every policy version.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from orthrus.cloud.models import CloudInventory, CloudResource
from orthrus.utils.logger import get_logger

logger = get_logger("cloud.collect")

ClientFactory = Callable[..., Any]


def _default_client_factory() -> ClientFactory:
    try:
        import boto3
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(
            "live AWS collection needs the [cloud] extra: pip install 'orthrus-framework[cloud]'"
        ) from exc
    session = boto3.Session()

    def factory(service: str, region: str | None = None) -> Any:
        return session.client(service, region_name=region)

    return factory


def _world_open_ports(ip_permissions: list[dict]) -> list[int]:
    ports: set[int] = set()
    for perm in ip_permissions or []:
        world = any(
            r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])
        ) or any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
        if not world:
            continue
        lo, hi = perm.get("FromPort"), perm.get("ToPort")
        if lo is None:  # all ports
            ports.update({22, 3389, 3306, 5432, 6379, 27017})
        elif lo == hi:
            ports.add(int(lo))
        else:
            ports.update(range(int(lo), min(int(hi), int(lo) + 1024) + 1))
    return sorted(ports)


def _collect_s3(cf: ClientFactory) -> list[CloudResource]:
    out: list[CloudResource] = []
    try:
        c = cf("s3")
        for b in c.list_buckets().get("Buckets", []):
            name = b.get("Name", "")
            public = False
            try:
                pab = c.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
                public = not all(pab.get(k, False) for k in
                                 ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
            except Exception:  # noqa: BLE001 - no block config often means "not blocked" = public-capable
                public = True
            encrypted = True
            try:
                c.get_bucket_encryption(Bucket=name)
            except Exception:  # noqa: BLE001 - ServerSideEncryptionConfigurationNotFoundError ⇒ unencrypted
                encrypted = False
            out.append(CloudResource(
                id=f"arn:aws:s3:::{name}", type="s3-bucket", name=name,
                public=public, encrypted=encrypted,
            ))
    except Exception as exc:  # noqa: BLE001
        logger.warning("S3 collection failed: %s", exc)
    return out


def _collect_ec2(cf: ClientFactory, region: str) -> list[CloudResource]:
    out: list[CloudResource] = []
    try:
        c = cf("ec2", region)
        sg_ports: dict[str, list[int]] = {}
        for sg in c.describe_security_groups().get("SecurityGroups", []):
            sg_ports[sg.get("GroupId", "")] = _world_open_ports(sg.get("IpPermissions", []))
        for res in c.describe_instances().get("Reservations", []):
            for inst in res.get("Instances", []):
                iid = inst.get("InstanceId", "")
                public = bool(inst.get("PublicIpAddress"))
                ports: set[int] = set()
                for sg in inst.get("SecurityGroups", []):
                    ports.update(sg_ports.get(sg.get("GroupId", ""), []))
                profile = inst.get("IamInstanceProfile", {}) or {}
                roles = [profile["Arn"]] if profile.get("Arn") else []
                out.append(CloudResource(
                    id=iid, type="ec2-instance", name=iid, region=region,
                    public=public, open_ports=sorted(ports), attached_roles=roles,
                ))
    except Exception as exc:  # noqa: BLE001
        logger.warning("EC2 collection failed in %s: %s", region, exc)
    return out


def _collect_rds(cf: ClientFactory, region: str) -> list[CloudResource]:
    out: list[CloudResource] = []
    try:
        c = cf("rds", region)
        for db in c.describe_db_instances().get("DBInstances", []):
            out.append(CloudResource(
                id=db.get("DBInstanceArn", db.get("DBInstanceIdentifier", "")),
                type="rds-instance", name=db.get("DBInstanceIdentifier", ""), region=region,
                public=bool(db.get("PubliclyAccessible")), encrypted=bool(db.get("StorageEncrypted")),
            ))
    except Exception as exc:  # noqa: BLE001
        logger.warning("RDS collection failed in %s: %s", region, exc)
    return out


def _collect_iam(cf: ClientFactory) -> list[CloudResource]:
    out: list[CloudResource] = []
    try:
        c = cf("iam")
        for u in c.list_users().get("Users", []):
            uname = u.get("UserName", "")
            attached = c.list_attached_user_policies(UserName=uname).get("AttachedPolicies", [])
            names = [p.get("PolicyName", "") for p in attached]
            perms = ["*"] if any(n in ("AdministratorAccess", "IAMFullAccess") for n in names) else names
            mfa = bool(c.list_mfa_devices(UserName=uname).get("MFADevices", []))
            out.append(CloudResource(
                id=u.get("Arn", uname), type="iam-user", name=uname,
                permissions=perms, mfa_enabled=mfa,
            ))
    except Exception as exc:  # noqa: BLE001
        logger.warning("IAM collection failed: %s", exc)
    return out


def collect_aws(
    *, client_factory: ClientFactory | None = None, regions: tuple[str, ...] = ("us-east-1",),
    account_id: str = "",
) -> CloudInventory:
    """Collect a read-only inventory from AWS (or an injected fake factory)."""
    cf = client_factory or _default_client_factory()
    resources: list[CloudResource] = []
    resources += _collect_s3(cf)
    resources += _collect_iam(cf)
    for region in regions:
        resources += _collect_ec2(cf, region)
        resources += _collect_rds(cf, region)
    return CloudInventory(provider="aws", account_id=account_id, resources=resources)


__all__ = ["collect_aws"]
