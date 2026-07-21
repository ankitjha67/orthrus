"""Internal-IP classifier + the internal-exposure scanner.

A public hostname resolving to non-routable space (RFC1918 / loopback / link-local
/ CGNAT / IPv6 ULA / cloud metadata) is flagged as internal-topology disclosure.
"""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Aggressiveness, Severity
from orthrus.scanners.internal_exposure import InternalExposureScanner
from orthrus.scanners.registry import SCANNER_REGISTRY
from orthrus.utils.ip_classify import classify_ip, is_internal


# ---------------------------------------------------------------- classifier
def test_classifies_each_non_public_category():
    assert classify_ip("10.0.0.5") == "private"
    assert classify_ip("172.16.9.9") == "private"
    assert classify_ip("192.168.1.1") == "private"
    assert classify_ip("127.0.0.1") == "loopback"
    assert classify_ip("100.64.0.1") == "cgnat"
    assert classify_ip("fc00::1") == "unique-local"


def test_metadata_wins_over_link_local():
    # 169.254.169.254 lives inside 169.254.0.0/16 but must classify as metadata.
    assert classify_ip("169.254.169.254") == "cloud-metadata"
    assert classify_ip("169.254.1.1") == "link-local"


def test_public_and_garbage_are_not_flagged():
    assert classify_ip("8.8.8.8") is None
    assert classify_ip("1.1.1.1") is None
    assert classify_ip("not-an-ip") is None
    assert is_internal("8.8.8.8") is False and is_internal("10.1.1.1") is True


# ---------------------------------------------------------------- scanner
def _asset(fqdn: str, *ips: str) -> SimpleNamespace:
    return SimpleNamespace(fqdn=fqdn, ips=list(ips))


def _ctx(*assets: object) -> SimpleNamespace:
    return SimpleNamespace(assets=list(assets))


def test_scanner_registered_and_passive():
    assert "internal-exposure" in SCANNER_REGISTRY
    assert InternalExposureScanner.min_aggressiveness == Aggressiveness.PASSIVE


async def test_flags_internal_resolving_subdomain():
    ctx = _ctx(_asset("internal.example.com", "10.0.0.5"),
               _asset("www.example.com", "203.0.113.10"))  # public -> ignored
    findings = [f async for f in InternalExposureScanner().scan(ctx)]
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "internal-ip-disclosure" and f.severity == Severity.MEDIUM
    assert "internal.example.com" in f.title and "10.0.0.5" in (f.evidence.notes or "")


async def test_metadata_record_is_high_severity():
    ctx = _ctx(_asset("weird.example.com", "169.254.169.254"))
    (f,) = [x async for x in InternalExposureScanner().scan(ctx)]
    assert f.severity == Severity.HIGH and "metadata" in f.description.lower()


async def test_public_only_and_empty_produce_nothing():
    ctx = _ctx(_asset("api.example.com", "8.8.8.8"), _asset("no-ip.example.com"))
    assert [f async for f in InternalExposureScanner().scan(ctx)] == []
    assert [f async for f in InternalExposureScanner().scan(_ctx())] == []


async def test_dedupes_by_fqdn():
    ctx = _ctx(_asset("dup.example.com", "10.0.0.1"), _asset("dup.example.com", "10.0.0.2"))
    findings = [f async for f in InternalExposureScanner().scan(ctx)]
    assert len(findings) == 1
