"""SSRF→IMDS escalation: cloud-credential extraction + redaction."""

from __future__ import annotations

from orthrus.scanners._cloud_metadata import extract_credentials, redact_secret
from orthrus.scanners.ssrf import detect_metadata_leak

_AWS = (
    '{"Code":"Success","LastUpdated":"2026-06-02T11:00:00Z","Type":"AWS-HMAC",'
    '"AccessKeyId":"ASIAIOSFODNN7EXAMPLE",'
    '"SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",'
    '"Token":"IQoJb3JpZ2luX2VjEXAMPLESESSIONTOKEN","Expiration":"2026-06-02T17:00:00Z"}'
)
_GCP = '{"access_token":"ya29.c.b0AXEXAMPLEgcptoken","expires_in":3599,"token_type":"Bearer"}'
_AZURE = (
    '{"access_token":"eyJ0eXAiOiJKV1QiLEXAMPLE","client_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890",'
    '"expires_on":"1717329600","resource":"https://management.azure.com/"}'
)


def test_redact_secret_is_non_recoverable():
    out = redact_secret("supersecretvalue1234")
    assert out.startswith("supe") and "chars" in out
    assert "secretvalue" not in out
    assert redact_secret("") == ""


def test_extract_aws_credentials():
    creds = extract_credentials(_AWS)
    assert creds.provider == "aws"
    assert creds.fields["AccessKeyId"] == "ASIAIOSFODNN7EXAMPLE"  # identifier kept
    # secrets redacted — never stored in full
    assert "wJalrXUtnFEMI" not in creds.fields["SecretAccessKey"]
    assert "chars" in creds.fields["SecretAccessKey"]
    assert "IQoJ" in creds.fields["Token"] and "SESSIONTOKEN" not in creds.fields["Token"]
    assert creds.fields["Expiration"] == "2026-06-02T17:00:00Z"


def test_extract_gcp_token():
    creds = extract_credentials(_GCP)
    assert creds.provider == "gcp"
    assert "ya29" in creds.fields["access_token"]
    assert "gcptoken" not in creds.fields["access_token"]  # redacted


def test_extract_azure_token_disambiguated_from_gcp():
    # Azure also has access_token + Bearer-ish JWT, but a client_id marks it Azure.
    creds = extract_credentials(_AZURE)
    assert creds.provider == "azure"
    assert creds.fields["client_id"] == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    assert creds.fields["access_token"].startswith("eyJ0")  # prefix kept
    assert "JV1Q" not in creds.fields["access_token"]        # body redacted


def test_metadata_without_credentials_returns_none():
    # Reachable metadata but no creds in the body → no escalation.
    body = '{"ami-id":"ami-0abc","instance-id":"i-0123","instance-type":"t3.micro"}'
    assert detect_metadata_leak(body) is True   # still flags metadata reach
    assert extract_credentials(body) is None     # but no credential theft


def test_no_metadata_no_creds():
    assert extract_credentials('{"hello":"world"}') is None
    assert extract_credentials("") is None
