"""On-the-fly CA + per-host leaf certs for TLS interception."""

from __future__ import annotations

import ssl

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding

from orthrus.proxy.ca import CertAuthority, generate_ca, leaf_cert


def test_generate_ca_is_a_ca():
    cert_pem, key_pem = generate_ca()
    cert = x509.load_pem_x509_certificate(cert_pem)
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True
    assert key_pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----")
    assert "ORTHRUS Proxy CA" in cert.subject.rfc4514_string()


def test_leaf_is_signed_by_ca_with_correct_san():
    ca_cert_pem, ca_key_pem = generate_ca()
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

    cert_pem, _key = leaf_cert("app.1win.com", ca_cert_pem, ca_key_pem)
    leaf = x509.load_pem_x509_certificate(cert_pem)

    # issued by the CA, and NOT itself a CA
    assert leaf.issuer == ca_cert.subject
    assert leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    # SAN carries the DNS host
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["app.1win.com"]
    # the leaf signature verifies against the CA public key (real chain of trust)
    ca_cert.public_key().verify(
        leaf.signature, leaf.tbs_certificate_bytes,
        padding.PKCS1v15(), leaf.signature_hash_algorithm)


def test_leaf_for_ip_uses_ip_san():
    ca_cert_pem, ca_key_pem = generate_ca()
    cert_pem, _ = leaf_cert("127.0.0.1", ca_cert_pem, ca_key_pem)
    san = x509.load_pem_x509_certificate(cert_pem).extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value
    import ipaddress
    assert san.get_values_for_type(x509.IPAddress) == [ipaddress.ip_address("127.0.0.1")]


def test_cert_authority_persists_and_serves_contexts(tmp_path):
    ca = CertAuthority(tmp_path)
    path = ca.ensure()
    assert path.exists() and ca.ca_key_path.exists()
    # idempotent: a second CA over the same home reuses the files, not regenerates
    fingerprint = ca.ca_cert_path.read_bytes()
    ca2 = CertAuthority(tmp_path)
    ca2.ensure()
    assert ca2.ca_cert_path.read_bytes() == fingerprint

    ctx = ca.ssl_context_for("app.1win.com")
    assert isinstance(ctx, ssl.SSLContext)
    assert ca.ssl_context_for("app.1win.com") is ctx      # cached per host
    assert ca.ssl_context_for("1w.cash") is not ctx
