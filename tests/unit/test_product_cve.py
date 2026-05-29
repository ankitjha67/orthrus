"""Product-fingerprint -> known-CVE scanner (version-less, WebLogic et al.)."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Confidence, Severity, Technology
from orthrus.intel.cve_intel import enrich
from orthrus.scanners.product_cve import (
    PRODUCTS,
    ProductCveScanner,
    extract_version,
    match_signature,
    origins_from,
    tech_match,
)

WEBLOGIC = next(p for p in PRODUCTS if p.key == "oracle-weblogic")
JENKINS = next(p for p in PRODUCTS if p.key == "jenkins")
CONFLUENCE = next(p for p in PRODUCTS if p.key == "atlassian-confluence")


# ---------------------------------------------------------------- pure detectors
def test_weblogic_kev_cves_are_in_seed():
    # The fix pairs product detection with the KEV intel; these must be KEV-listed.
    for cid in ("CVE-2020-14882", "CVE-2017-10271", "CVE-2023-21839"):
        assert enrich(cid).kev is True


def test_match_signature_weblogic_body():
    body = "<html><title>Oracle WebLogic Server Administration Console</title></html>"
    assert match_signature(WEBLOGIC, {}, body, 200) is True


def test_match_signature_weblogic_server_header():
    assert match_signature(WEBLOGIC, {"Server": "WebLogic Server 12.2.1"}, "", 200) is True


def test_match_signature_requires_a_marker():
    # A bare 200 with an unrelated body must not match (no false positive).
    assert match_signature(WEBLOGIC, {"Server": "nginx"}, "<html>hi</html>", 200) is False


def test_match_signature_ignores_server_error_body():
    # Body markers on a 5xx error page are unreliable -> no match.
    assert match_signature(WEBLOGIC, {}, "WebLogic Server", 500) is False


def test_extract_version_weblogic_none_when_absent():
    body = "<title>Oracle WebLogic Server Administration Console</title>"
    assert extract_version(WEBLOGIC, {}, body) is None


def test_extract_version_jenkins_from_header():
    headers = {"X-Jenkins": "2.426.1"}
    assert extract_version(JENKINS, headers, "") == "2.426.1"


def test_extract_version_confluence_from_meta():
    body = '<meta name="ajs-version-number" content="7.18.0">'
    assert extract_version(CONFLUENCE, {}, body) == "7.18.0"


def test_tech_match_from_recon_fingerprint():
    techs = [Technology(name="Oracle WebLogic", version="12.2.1.4")]
    hit, version = tech_match(WEBLOGIC, techs)
    assert hit is True
    assert version == "12.2.1.4"


def test_tech_match_miss():
    hit, version = tech_match(WEBLOGIC, [Technology(name="nginx")])
    assert hit is False and version is None


def test_origins_dedup():
    origins = origins_from("https://h:7001/console/", ["https://h:7001/app", "http://other/"])
    assert origins == ["https://h:7001", "http://other"]


# ---------------------------------------------------------------- full scan flow
class _FakeResp:
    def __init__(self, status: int, text: str, headers: dict[str, str] | None = None) -> None:
        self.status_code = status
        self.text = text
        self.headers = headers or {}


class _WebLogicHttp:
    """Serves a WebLogic console login page at /console/login/LoginForm.jsp."""

    async def get(self, url: str, **kw: object) -> _FakeResp:
        if "LoginForm.jsp" in url:
            return _FakeResp(
                200,
                "<html><head><title>Oracle WebLogic Server Administration Console</title></head>"
                "<body>Welcome to the WebLogic Server</body></html>",
            )
        return _FakeResp(404, "<html>404</html>")


def _ctx(http: object, target: str) -> SimpleNamespace:
    return SimpleNamespace(
        endpoints=[],
        assets=[],
        http=http,
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(target=target),
    )


async def test_full_scan_flags_versionless_weblogic():
    ctx = _ctx(_WebLogicHttp(), "https://h:7001/console/login/LoginForm.jsp")
    findings = [f async for f in ProductCveScanner().scan(ctx)]
    wl = [f for f in findings if "WebLogic" in f.title]
    assert len(wl) == 1
    f = wl[0]
    assert f.vuln_type == "cve"
    assert f.severity == Severity.CRITICAL
    # Version-less detection -> TENTATIVE, but the exposure is reported.
    assert f.confidence == Confidence.TENTATIVE
    assert "CISA-KEV" in f.title
    assert "CVE-2020-14882" in f.description
    assert "version not disclosed" in f.title


async def test_full_scan_uses_recon_version_when_present():
    ctx = _ctx(_WebLogicHttp(), "https://h:7001/")
    ctx.assets = [SimpleNamespace(technologies=[Technology(name="Oracle WebLogic", version="12.2.1.4")])]
    findings = [f async for f in ProductCveScanner().scan(ctx)]
    wl = [f for f in findings if "WebLogic" in f.title]
    assert len(wl) == 1
    # A recovered version makes the detection firm and is shown in the title.
    assert wl[0].confidence == Confidence.FIRM
    assert "12.2.1.4" in wl[0].title


async def test_no_finding_on_unrelated_host():
    class _Plain:
        async def get(self, url: str, **kw: object) -> _FakeResp:
            return _FakeResp(200, "<html>just a website</html>", {"Server": "nginx"})

    findings = [f async for f in ProductCveScanner().scan(_ctx(_Plain(), "https://h/"))]
    assert findings == []
