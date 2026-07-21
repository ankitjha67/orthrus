"""On-the-fly Certificate Authority for TLS interception (Burp/Caido-style MITM).

Generates a local CA once (stored under ``$ORTHRUS_HOME/proxy-ca/``), then mints a
per-host leaf certificate signed by it on demand so the intercepting proxy can
terminate TLS for an in-scope host and read the plaintext. Install the CA cert in
your browser/OS trust store (``orthrus proxy --export-ca``) so HTTPS shows no
warning - exactly the Burp/Caido setup step.

The CA private key never leaves your host. Only in-scope hosts are ever
intercepted (the proxy enforces that); everything else is tunneled opaquely.
"""

from __future__ import annotations

import ipaddress
import ssl
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_CA_CN = "ORTHRUS Proxy CA"


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def generate_ca() -> tuple[bytes, bytes]:
    """Generate a self-signed CA certificate + private key (both PEM bytes)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, _CA_CN),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ORTHRUS"),
    ])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False),
            critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return _pem(cert), _key_pem(key)


def leaf_cert(host: str, ca_cert_pem: bytes, ca_key_pem: bytes) -> tuple[bytes, bytes]:
    """Mint a leaf certificate for ``host``, signed by the CA (PEM cert + key)."""
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    try:
        san: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        san = x509.DNSName(host)
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName([san]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return _pem(cert), _key_pem(key)


class CertAuthority:
    """Persistent CA + a per-host leaf-cert cache for the intercepting proxy."""

    def __init__(self, home: Path) -> None:
        self.dir = Path(home) / "proxy-ca"
        self.ca_cert_path = self.dir / "orthrus-ca.crt"
        self.ca_key_path = self.dir / "orthrus-ca.key"
        self._ca_cert_pem: bytes | None = None
        self._ca_key_pem: bytes | None = None
        self._ctx_cache: dict[str, ssl.SSLContext] = {}
        self._leaf_dir: Path | None = None

    def ensure(self) -> Path:
        """Create the CA on first use; return the CA certificate path (to install)."""
        if not (self.ca_cert_path.exists() and self.ca_key_path.exists()):
            self.dir.mkdir(parents=True, exist_ok=True)
            cert_pem, key_pem = generate_ca()
            self.ca_cert_path.write_bytes(cert_pem)
            self.ca_key_path.write_bytes(key_pem)
            try:
                self.ca_key_path.chmod(0o600)   # best-effort on POSIX
            except OSError:
                pass
        self._ca_cert_pem = self.ca_cert_path.read_bytes()
        self._ca_key_pem = self.ca_key_path.read_bytes()
        return self.ca_cert_path

    def ssl_context_for(self, host: str) -> ssl.SSLContext:
        """A server-side SSLContext presenting a leaf cert for ``host`` (cached per host)."""
        if host in self._ctx_cache:
            return self._ctx_cache[host]
        if self._ca_cert_pem is None or self._ca_key_pem is None:
            self.ensure()
        cert_pem, key_pem = leaf_cert(host, self._ca_cert_pem, self._ca_key_pem)
        if self._leaf_dir is None:
            self._leaf_dir = Path(tempfile.mkdtemp(prefix="orthrus-leaf-"))
        safe = host.replace(":", "_").replace("/", "_")
        cert_file = self._leaf_dir / f"{safe}.crt"
        key_file = self._leaf_dir / f"{safe}.key"
        cert_file.write_bytes(cert_pem)
        key_file.write_bytes(key_pem)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
        self._ctx_cache[host] = ctx
        return ctx


__all__ = ["generate_ca", "leaf_cert", "CertAuthority"]
