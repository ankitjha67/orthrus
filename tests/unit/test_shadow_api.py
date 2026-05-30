"""Shadow / improper-inventory API scanner tests.

Covers the pure detectors (version_variants segment-swapping, reachable_variant
soft-404 suppression) plus the scanner end-to-end against duck-typed fakes,
including the soft-404 calibration that prevents catch-all false positives.
"""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Severity
from orthrus.scanners.shadow_api import (
    ShadowApiScanner,
    reachable_variant,
    version_variants,
)


# ------------------------------------------------------------- pure detectors
def test_version_variants_swaps_api_version_segment() -> None:
    out = version_variants("http://h/api/v2/users")
    assert "http://h/api/v1/users" in out
    assert "http://h/api/internal/users" in out
    assert "http://h/api/admin/users" in out
    # the original v2 segment is excluded
    assert "http://h/api/v2/users" not in out


def test_version_variants_handles_internal_and_beta_segments() -> None:
    out = version_variants("http://h/internal/report")
    # original "internal" excluded, but v1/beta/admin variants present
    assert "http://h/internal/report" not in out
    assert "http://h/v1/report" in out
    assert "http://h/beta/report" in out


def test_version_variants_empty_without_version_segment() -> None:
    assert version_variants("http://h/users/profile") == []
    assert version_variants("http://h/") == []
    assert version_variants("not-a-url") == []


def test_reachable_variant_status_gate() -> None:
    assert reachable_variant(200, "ok", 404, "nope") is True
    assert reachable_variant(401, "auth", 404, "nope") is True
    assert reachable_variant(403, "deny", 404, "nope") is True
    assert reachable_variant(500, "err", 404, "nope") is False
    assert reachable_variant(404, "nope", 404, "nope") is False


def test_reachable_variant_suppresses_soft_404_catchall() -> None:
    # Same status AND body as the calibrated soft-404 -> not reachable.
    assert reachable_variant(200, "  catch-all  ", 200, "catch-all") is False
    # Same status but distinct body -> reachable.
    assert reachable_variant(200, "real v1 payload", 200, "catch-all") is True


# ------------------------------------------------------------ scanner harness
class FakeResp:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text
        self.headers: dict[str, str] = {}
        self.content_type: str | None = None


def _ctx(http: object, endpoints: list[object]) -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(target="http://h/"),
        endpoints=endpoints,
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        http=http,
    )


def _ep(url: str) -> SimpleNamespace:
    return SimpleNamespace(url=url)


class ShadowHttp:
    """Origin where an old /v1 still answers 200 and /internal requires auth."""

    async def get(self, url: str, **kw: object) -> FakeResp:
        if "/orthrus-shadow-" in url:  # soft-404 calibration probe
            return FakeResp(404, "not found")
        if "/v1/" in url:
            return FakeResp(200, "legacy v1 user payload")
        if "/internal/" in url:
            return FakeResp(403, "forbidden")
        return FakeResp(404, "not found")


class CatchAllHttp:
    """Every path returns the same 200 body (a catch-all that must not FP)."""

    async def get(self, url: str, **kw: object) -> FakeResp:
        return FakeResp(200, "homepage")


async def test_scanner_flags_old_version_and_gated_internal() -> None:
    ctx = _ctx(ShadowHttp(), [_ep("http://h/api/v2/users")])
    findings = [f async for f in ShadowApiScanner().scan(ctx)]
    sa = [f for f in findings if f.vuln_type == "shadow-api"]
    urls = " ".join(f.url for f in sa)
    assert "/api/v1/users" in urls
    assert "/api/internal/users" in urls
    # the 200 v1 is MEDIUM, the 403 internal is LOW
    v1 = next(f for f in sa if "/v1/" in f.url)
    internal = next(f for f in sa if "/internal/" in f.url)
    assert v1.severity == Severity.MEDIUM
    assert internal.severity == Severity.LOW
    assert all(f.cwe == "CWE-668" for f in sa)
    assert all(f.evidence.matched_at.startswith("HTTP ") for f in sa)


async def test_scanner_suppresses_catchall_origin() -> None:
    ctx = _ctx(CatchAllHttp(), [_ep("http://h/api/v2/users")])
    findings = [f async for f in ShadowApiScanner().scan(ctx)]
    # The soft-404 baseline equals every variant response -> nothing reachable.
    assert [f for f in findings if f.vuln_type == "shadow-api"] == []


async def test_scanner_quiet_without_versioned_endpoints() -> None:
    ctx = _ctx(ShadowHttp(), [_ep("http://h/users/profile")])
    findings = [f async for f in ShadowApiScanner().scan(ctx)]
    assert [f for f in findings if f.vuln_type == "shadow-api"] == []
