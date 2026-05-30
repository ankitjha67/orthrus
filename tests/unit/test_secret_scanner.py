"""Exposed-secret scanner tests.

Cover the pure ``find_secrets`` / ``is_scannable_body`` detectors (positive and
negative cases, plus redaction safety) and the scanner end-to-end against
duck-typed fakes.
"""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Severity
from orthrus.scanners.secret_scanner import (
    SecretScanner,
    find_secrets,
    is_scannable_body,
)

# Synthetic, well-formed-looking secrets (not real credentials).
_AWS = "AKIAABCDEFGHIJKLMNOP"
_STRIPE = "sk_live_" + "A1b2C3d4E5f6G7h8I9j0K1L2"
_GOOGLE = "AIza" + "B" * 35
_PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEoQ...\n-----END RSA PRIVATE KEY-----"


# --------------------------------------------------------------- pure detectors
def test_find_secrets_detects_aws_and_stripe() -> None:
    hits = find_secrets(f"const k='{_AWS}'; var s='{_STRIPE}';")
    labels = {label for label, _preview, _sev in hits}
    assert "AWS access key" in labels
    assert "Stripe live key" in labels
    sev_by_label = {label: sev for label, _preview, sev in hits}
    assert sev_by_label["AWS access key"] == Severity.HIGH
    assert sev_by_label["Stripe live key"] == Severity.CRITICAL


def test_find_secrets_detects_private_key_block() -> None:
    hits = find_secrets(_PEM)
    assert any(label == "Private key block" for label, _p, _s in hits)
    assert any(sev == Severity.CRITICAL for _l, _p, sev in hits)


def test_find_secrets_redacts_and_never_leaks_full_value() -> None:
    [(label, preview, _sev)] = find_secrets(f"key={_AWS}")
    assert label == "AWS access key"
    assert preview == _AWS[:4] + "***"
    assert _AWS not in preview  # full secret must not survive


def test_find_secrets_dedupes_repeated_match() -> None:
    hits = find_secrets(f"{_AWS} ... again {_AWS}")
    assert len(hits) == 1


def test_find_secrets_negative_on_benign_text() -> None:
    assert find_secrets("just some <html>content</html> with AKIA-too-short") == []
    assert find_secrets("AIzaTOOSHORT") == []


def test_is_scannable_body_filters_binary() -> None:
    assert is_scannable_body("text/html; charset=utf-8") is True
    assert is_scannable_body("application/json") is True
    assert is_scannable_body(None) is True
    assert is_scannable_body("image/png") is False
    assert is_scannable_body("application/octet-stream") is False
    assert is_scannable_body("font/woff2") is False


# ---------------------------------------------------------------- scanner harness
class FakeResp:
    def __init__(self, text: str, status_code: int = 200, content_type: str = "text/html"):
        self.text = text
        self.status_code = status_code
        self.headers = {"content-type": content_type}
        self.content_type = content_type


class SecretHttp:
    """Serves a leaking root page and a clean JS file."""

    async def get(self, url: str, **kw: object) -> FakeResp:
        if url.endswith("/app.js"):
            return FakeResp("console.log('clean');", content_type="application/javascript")
        return FakeResp(f"<script>var k='{_AWS}';</script>")


class CleanHttp:
    async def get(self, url: str, **kw: object) -> FakeResp:
        return FakeResp("<html>nothing secret here</html>")


def _ctx(http: object, endpoints: list[object] | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(target="http://h/"),
        endpoints=endpoints or [],
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        http=http,
    )


async def test_scanner_flags_leaked_secret() -> None:
    ep = SimpleNamespace(url="http://h/app.js", content_type="application/javascript")
    findings = [f async for f in SecretScanner().scan(_ctx(SecretHttp(), [ep]))]
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "exposed-secret"
    assert f.severity == Severity.HIGH
    assert f.cwe == "CWE-798"
    assert f.title == "Exposed secret: AWS access key"
    # evidence carries only the redacted preview, never the full secret.
    assert f.evidence.matched_at == _AWS[:4] + "***"
    assert _AWS not in (f.evidence.matched_at or "")


async def test_scanner_quiet_when_no_secrets() -> None:
    findings = [f async for f in SecretScanner().scan(_ctx(CleanHttp()))]
    assert findings == []


async def test_scanner_skips_binary_content_type() -> None:
    ep = SimpleNamespace(url="http://h/logo.png", content_type="image/png")
    # Only the image endpoint is offered; root target is clean.
    findings = [f async for f in SecretScanner().scan(_ctx(CleanHttp(), [ep]))]
    assert findings == []
