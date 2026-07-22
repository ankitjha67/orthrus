"""CDN detection + origin-IP exposure (CDN bypass) scanner."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Confidence, Severity
from orthrus.scanners.origin_exposure import (
    OriginExposureScanner,
    detect_cdn,
    exposed_origin_ips,
)
from orthrus.utils.cdn import cdn_of, is_cdn


# ------------------------------------------------------------ cdn ranges
def test_cdn_of_identifies_providers_and_ignores_others():
    assert cdn_of("104.16.1.1") == "Cloudflare"
    assert cdn_of("172.64.5.5") == "Cloudflare"
    assert cdn_of("151.101.1.1") == "Fastly"
    assert cdn_of("13.32.0.9") == "CloudFront"
    assert cdn_of("93.184.216.34") is None        # public, non-CDN
    assert cdn_of("10.0.0.1") is None              # internal
    assert cdn_of("not-an-ip") is None
    assert is_cdn("104.16.1.1") and not is_cdn("8.8.8.8")


# ------------------------------------------------------------ helpers
def _asset(fqdn: str, *ips: str) -> SimpleNamespace:
    return SimpleNamespace(fqdn=fqdn, ips=list(ips))


def test_detect_cdn_from_fully_fronted_asset():
    assert detect_cdn([_asset("www.t.com", "104.16.1.1")]) == "Cloudflare"
    assert detect_cdn([_asset("api.t.com", "93.184.216.34")]) is None      # no CDN anywhere


def test_exposed_origin_ips_excludes_cdn_and_internal():
    assert exposed_origin_ips(["104.16.1.1", "93.184.216.34", "10.0.0.1"]) == ["93.184.216.34"]


# ------------------------------------------------------------ scanner
def _ctx(*assets: object) -> SimpleNamespace:
    return SimpleNamespace(assets=list(assets))


async def test_flags_non_cdn_host_when_app_is_cdn_fronted():
    ctx = _ctx(
        _asset("www.t.com", "104.16.1.1"),          # Cloudflare-fronted -> app uses a CDN
        _asset("api.t.com", "93.184.216.34"),        # public non-CDN -> origin leak
    )
    findings = [f async for f in OriginExposureScanner().scan(ctx)]
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "origin-exposure" and f.severity == Severity.MEDIUM
    assert f.confidence == Confidence.TENTATIVE and "api.t.com" in f.title
    assert "Cloudflare" in f.description and "93.184.216.34" in (f.evidence.notes or "")


async def test_excludes_mail_and_dns_subdomains():
    ctx = _ctx(_asset("www.t.com", "104.16.1.1"),
               _asset("mail.t.com", "93.184.216.35"),
               _asset("ns1.t.com", "93.184.216.36"))
    assert [f async for f in OriginExposureScanner().scan(ctx)] == []


async def test_no_findings_without_a_cdn():
    # App not CDN-fronted -> no "origin" concept, even with public non-CDN hosts.
    ctx = _ctx(_asset("www.t.com", "93.184.216.34"), _asset("api.t.com", "93.184.216.35"))
    assert [f async for f in OriginExposureScanner().scan(ctx)] == []


async def test_fully_cdn_and_internal_only_hosts_not_flagged():
    ctx = _ctx(_asset("www.t.com", "104.16.1.1"),        # fully CDN -> fine
               _asset("cdn.t.com", "172.64.0.9"),         # fully CDN -> fine
               _asset("internal.t.com", "10.0.0.5"))      # internal -> internal-exposure's job
    assert [f async for f in OriginExposureScanner().scan(ctx)] == []
