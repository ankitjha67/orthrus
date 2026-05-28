"""Tests for the SSRF cloud-metadata signature detector."""

from __future__ import annotations

from hydra.scanners.ssrf import detect_metadata_leak


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
