"""Tests for the SSRF cloud-metadata signature detector."""

from __future__ import annotations

from orthrus.scanners._payloads import SSRF_METADATA
from orthrus.scanners.ssrf import detect_metadata_leak


def test_aws_metadata_signature():
    body = "ami-id\nami-launch-index\ninstance-id\ninstance-type\nlocal-ipv4\n"
    assert detect_metadata_leak(body) is True


def test_iam_credentials_signature():
    assert detect_metadata_leak('{"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"..."}') is True


def test_reflected_payload_url_is_not_flagged():
    # The injected payload URL contains 'security-credentials'/'computeMetadata';
    # an app that merely reflects it must NOT be reported as a metadata leak.
    reflected = "PING result: http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    assert detect_metadata_leak(reflected) is False


def test_normal_page_is_clean():
    assert detect_metadata_leak("<html><body>Welcome home</body></html>") is False


def test_metadata_payloads_include_obfuscation_bypasses():
    joined = " ".join(SSRF_METADATA)
    assert "0xa9fea9fe" in joined                # hex 169.254.169.254
    assert "0251.0376.0251.0376" in joined       # octal dotted-quad
    assert "169.254.169.254.nip.io" in joined    # DNS wildcard -> link-local
    assert "foo@169.254.169.254" in joined       # userinfo parser confusion


def test_no_metadata_payload_self_triggers_signature():
    # FP invariant: every injected payload URL, if merely reflected, must NOT match
    # a metadata-response signature - otherwise the obfuscation variants would
    # false-positive on reflection.
    for payload in SSRF_METADATA:
        assert detect_metadata_leak(payload) is False
