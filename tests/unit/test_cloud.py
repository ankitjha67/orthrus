"""Cloud posture (CSPM/IAM) - posture rules, toxic-combination graph, CLI, collector."""

from __future__ import annotations

import json

from click.testing import CliRunner

from orthrus import main
from orthrus.cloud.analyze import analyze_inventory
from orthrus.cloud.collect import collect_aws
from orthrus.cloud.models import CloudInventory, CloudResource
from orthrus.cloud.toxic import analyze_cloud, toxic_combinations
from orthrus.core.schemas import Severity


def _inv(*resources: CloudResource) -> CloudInventory:
    return CloudInventory(provider="aws", account_id="123456789012", resources=list(resources))


def _types(findings) -> list[str]:
    return [f.vuln_type for f in findings]


# --- posture rules -------------------------------------------------------

def test_public_bucket_high_and_sensitive_tag_critical():
    plain = analyze_inventory(_inv(CloudResource(id="arn:s3:::b", type="s3-bucket", public=True)))
    assert plain[0].vuln_type == "cloud-public-bucket"
    assert plain[0].severity == Severity.HIGH
    tagged = analyze_inventory(_inv(
        CloudResource(id="arn:s3:::b", type="s3-bucket", public=True, tags={"data": "PII"})
    ))
    assert tagged[0].severity == Severity.CRITICAL


def test_unencrypted_storage_medium():
    f = analyze_inventory(_inv(CloudResource(id="vol-1", type="ebs-volume", encrypted=False)))
    assert f[0].vuln_type == "cloud-unencrypted" and f[0].severity == Severity.MEDIUM


def test_wildcard_admin_and_no_mfa():
    f = analyze_inventory(_inv(
        CloudResource(id="arn:iam::u/a", type="iam-user", permissions=["*"], mfa_enabled=False)
    ))
    assert "cloud-iam-admin" in _types(f)
    assert "cloud-no-mfa" in _types(f)


def test_public_db_critical():
    f = analyze_inventory(_inv(CloudResource(id="db-1", type="rds-instance", public=True)))
    assert f[0].vuln_type == "cloud-public-db" and f[0].severity == Severity.CRITICAL


def test_sensitive_port_open_to_world():
    f = analyze_inventory(_inv(CloudResource(id="sg-1", type="security-group", open_ports=[22, 8080])))
    assert f[0].vuln_type == "cloud-open-port"
    assert "22/SSH" in f[0].evidence.notes and "8080" not in f[0].evidence.notes  # 8080 not sensitive


def test_clean_resource_yields_nothing():
    clean = CloudResource(id="arn:s3:::ok", type="s3-bucket", public=False, encrypted=True)
    assert analyze_inventory(_inv(clean)) == []


# --- toxic combinations --------------------------------------------------

def _priv_role(rid="arn:iam::1:role/admin"):
    return CloudResource(id=rid, type="iam-role", name="admin", permissions=["*"])


def test_public_compute_with_privileged_role_is_critical():
    ec2 = CloudResource(id="i-1", type="ec2-instance", public=True,
                        attached_roles=["arn:iam::1:role/admin"])
    combos = toxic_combinations(_inv(ec2, _priv_role()))
    assert len(combos) == 1
    assert combos[0].vuln_type == "cloud-toxic-combo"
    assert combos[0].severity == Severity.CRITICAL
    assert "i-1" in combos[0].description and "role/admin" in combos[0].description  # chain lists both


def test_open_admin_port_plus_privileged_role_is_critical():
    ec2 = CloudResource(id="i-2", type="ec2-instance", open_ports=[22],
                        attached_roles=["arn:iam::1:role/admin"])
    combos = toxic_combinations(_inv(ec2, _priv_role()))
    assert combos and combos[0].severity == Severity.CRITICAL


def test_exposed_compute_without_privilege_is_not_toxic():
    ec2 = CloudResource(id="i-3", type="ec2-instance", public=True,
                        attached_roles=["arn:iam::1:role/ro"])
    # A genuinely minimal permission - not one of the privilege fragments.
    ro = CloudResource(id="arn:iam::1:role/ro", type="iam-role",
                       permissions=["cloudwatch:PutMetricData"])
    assert toxic_combinations(_inv(ec2, ro)) == []


def test_privileged_role_but_not_exposed_is_not_toxic():
    ec2 = CloudResource(id="i-4", type="ec2-instance", public=False,
                        attached_roles=["arn:iam::1:role/admin"])
    assert toxic_combinations(_inv(ec2, _priv_role())) == []


def test_admin_user_without_mfa_is_toxic_critical():
    u = CloudResource(id="arn:iam::1:user/root", type="iam-user", permissions=["*"], mfa_enabled=False)
    combos = toxic_combinations(_inv(u))
    assert any("without MFA" in c.title for c in combos)
    assert combos[0].severity == Severity.CRITICAL


def test_passrole_escalation_combo():
    p = CloudResource(id="arn:iam::1:role/ci", type="iam-role",
                      permissions=["iam:PassRole", "ec2:RunInstances"])
    combos = toxic_combinations(_inv(p))
    assert any("privilege-escalation" in c.title for c in combos)
    assert combos[0].severity == Severity.HIGH


def test_analyze_cloud_puts_toxic_first():
    ec2 = CloudResource(id="i-9", type="ec2-instance", public=True,
                        attached_roles=["arn:iam::1:role/admin"])
    findings = analyze_cloud(_inv(ec2, _priv_role()))
    assert findings[0].vuln_type == "cloud-toxic-combo"  # combos precede posture findings


# --- model parsing -------------------------------------------------------

def test_inventory_from_dict_is_tolerant():
    inv = CloudInventory.from_dict({
        "provider": "aws", "account_id": "1",
        "resources": [
            {"id": "b", "type": "s3-bucket", "public": True, "open_ports": ["22", "x", 3306]},
            "not-a-dict",
            {"type": "iam-user", "permissions": "s3:*", "tags": {"env": "prod"}},
        ],
    })
    assert len(inv.resources) == 2
    assert inv.resources[0].open_ports == [22, 3306]  # coerced, junk dropped
    assert inv.resources[1].permissions == ["s3:*"]  # scalar → list
    assert inv.resources[1].id == "unknown"  # missing id falls back


# --- CLI -----------------------------------------------------------------

def _write_snapshot(tmp_path) -> str:
    snap = {
        "provider": "aws", "account_id": "123456789012",
        "resources": [
            {"id": "i-1", "type": "ec2-instance", "public": True, "attached_roles": ["arn:iam::1:role/admin"]},
            {"id": "arn:iam::1:role/admin", "type": "iam-role", "name": "admin", "permissions": ["*"]},
            {"id": "arn:s3:::open", "type": "s3-bucket", "public": True},
        ],
    }
    p = tmp_path / "inv.json"
    p.write_text(json.dumps(snap), encoding="utf-8")
    return str(p)


def test_cli_cloud_reports_findings(tmp_path):
    r = CliRunner().invoke(main.cli, ["--no-banner", "cloud", _write_snapshot(tmp_path)])
    assert r.exit_code == 0, r.output
    assert "toxic combination" in r.output


def test_cli_cloud_json_output_and_fail_on(tmp_path):
    out = tmp_path / "out.json"
    r = CliRunner().invoke(main.cli, [
        "--no-banner", "cloud", _write_snapshot(tmp_path), "-o", str(out), "--fail-on", "high",
    ])
    assert r.exit_code == 1  # a critical toxic combo trips --fail-on high
    data = json.loads(out.read_text(encoding="utf-8"))
    types = [f["vuln_type"] for f in data["findings"]]
    assert "cloud-toxic-combo" in types and "cloud-public-bucket" in types


def test_cli_cloud_toxic_only(tmp_path):
    out = tmp_path / "t.json"
    CliRunner().invoke(main.cli, [
        "--no-banner", "cloud", _write_snapshot(tmp_path), "--toxic-only", "-o", str(out),
    ])
    types = {f["vuln_type"] for f in json.loads(out.read_text(encoding="utf-8"))["findings"]}
    assert types == {"cloud-toxic-combo"}  # posture findings suppressed


def test_cli_cloud_requires_input():
    r = CliRunner().invoke(main.cli, ["--no-banner", "cloud"])
    assert r.exit_code != 0
    assert "SNAPSHOT" in r.output or "snapshot" in r.output or "--live" in r.output


# --- read-only collector (fake boto3, no live creds) ---------------------

class _FakeClient:
    def __init__(self, table: dict):
        self._table = table

    def __getattr__(self, name):
        def _call(**kwargs):
            val = self._table.get(name, {})
            if isinstance(val, Exception):
                raise val
            return val
        return _call


def _fake_factory():
    tables = {
        "s3": {
            "list_buckets": {"Buckets": [{"Name": "public-bucket"}]},
            "get_public_access_block": {"PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False, "IgnorePublicAcls": False,
                "BlockPublicPolicy": False, "RestrictPublicBuckets": False}},
            "get_bucket_encryption": RuntimeError("ServerSideEncryptionConfigurationNotFoundError"),
        },
        "iam": {
            "list_users": {"Users": [{"UserName": "admin", "Arn": "arn:aws:iam::1:user/admin"}]},
            "list_attached_user_policies": {"AttachedPolicies": [{"PolicyName": "AdministratorAccess"}]},
            "list_mfa_devices": {"MFADevices": []},
        },
        "ec2": {
            "describe_security_groups": {"SecurityGroups": [
                {"GroupId": "sg-1", "IpPermissions": [
                    {"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]},
            "describe_instances": {"Reservations": [{"Instances": [
                {"InstanceId": "i-1", "PublicIpAddress": "1.2.3.4",
                 "SecurityGroups": [{"GroupId": "sg-1"}],
                 "IamInstanceProfile": {"Arn": "arn:aws:iam::1:instance-profile/app"}}]}]},
        },
        "rds": {
            "describe_db_instances": {"DBInstances": [
                {"DBInstanceArn": "arn:aws:rds:us-east-1:1:db:maindb",
                 "DBInstanceIdentifier": "maindb", "PubliclyAccessible": True, "StorageEncrypted": False}]},
        },
    }

    def cf(service, region=None):
        return _FakeClient(tables[service])

    return cf


def test_collect_aws_normalizes_read_only():
    inv = collect_aws(client_factory=_fake_factory(), regions=("us-east-1",), account_id="1")
    by_type = {r.type: r for r in inv.resources}
    assert by_type["s3-bucket"].public is True and by_type["s3-bucket"].encrypted is False
    assert by_type["iam-user"].permissions == ["*"] and by_type["iam-user"].mfa_enabled is False
    assert by_type["ec2-instance"].public is True and by_type["ec2-instance"].open_ports == [22]
    assert by_type["ec2-instance"].attached_roles == ["arn:aws:iam::1:instance-profile/app"]
    assert by_type["rds-instance"].public is True and by_type["rds-instance"].encrypted is False
