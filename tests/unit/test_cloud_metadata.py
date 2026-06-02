"""SSRF→IMDS escalation: cloud-credential extraction + redaction."""

from __future__ import annotations

from orthrus.scanners._cloud_metadata import extract_credentials, redact_secret
from orthrus.scanners.ssrf import detect_metadata_leak

# NOTE: these are deliberately NON-credential placeholders — they only exercise
# the JSON-shape extraction/redaction logic. Real-looking AWS/GCP/Azure token
# shapes are avoided on purpose so secret scanners don't flag the fixtures.
_AWS = (
    '{"Code":"Success","LastUpdated":"2026-06-02T11:00:00Z","Type":"AWS-HMAC",'
    '"AccessKeyId":"PLACEHOLDER-not-a-real-access-key-id",'
    '"SecretAccessKey":"PLACEHOLDER-not-a-real-secret-access-key",'
    '"Token":"PLACEHOLDER-not-a-real-session-token","Expiration":"2026-06-02T17:00:00Z"}'
)
_GCP = '{"access_token":"PLACEHOLDER-not-a-real-gcp-token","expires_in":3599,"token_type":"Bearer"}'
_AZURE = (
    '{"access_token":"PLACEHOLDER-not-a-real-azure-token",'
    '"client_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890",'
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
    assert creds.fields["AccessKeyId"] == "PLACEHOLDER-not-a-real-access-key-id"  # identifier kept
    # secrets redacted — never stored in full
    assert "real-secret-access-key" not in creds.fields["SecretAccessKey"]
    assert "chars" in creds.fields["SecretAccessKey"]
    assert "real-session-token" not in creds.fields["Token"] and "chars" in creds.fields["Token"]
    assert creds.fields["Expiration"] == "2026-06-02T17:00:00Z"


def test_extract_gcp_token():
    # No real Google token shape in the fixture; classification rides the Bearer marker.
    creds = extract_credentials(_GCP)
    assert creds.provider == "gcp"
    assert creds.fields["access_token"].startswith("PLAC")  # prefix kept
    assert "real-gcp-token" not in creds.fields["access_token"]  # redacted


def test_extract_azure_token_disambiguated_from_gcp():
    # Azure also carries access_token + token, but a client_id marks it Azure.
    creds = extract_credentials(_AZURE)
    assert creds.provider == "azure"
    assert creds.fields["client_id"] == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    assert creds.fields["access_token"].startswith("PLAC")  # prefix kept
    assert "real-azure-token" not in creds.fields["access_token"]  # body redacted


def test_metadata_without_credentials_returns_none():
    # Reachable metadata but no creds in the body → no escalation.
    body = '{"ami-id":"ami-0abc","instance-id":"i-0123","instance-type":"t3.micro"}'
    assert detect_metadata_leak(body) is True   # still flags metadata reach
    assert extract_credentials(body) is None     # but no credential theft


def test_no_metadata_no_creds():
    assert extract_credentials('{"hello":"world"}') is None
    assert extract_credentials("") is None
