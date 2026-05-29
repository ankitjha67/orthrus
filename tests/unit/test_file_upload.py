"""Unrestricted file-upload scanner."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Severity
from orthrus.scanners.file_upload import (
    FileUploadScanner,
    is_upload_endpoint,
    upload_accepted,
)


def test_is_upload_endpoint() -> None:
    assert is_upload_endpoint("http://h/upload") is True
    assert is_upload_endpoint("http://h/user/avatar") is True
    assert is_upload_endpoint("http://h/api/save", ("attachment",)) is True
    assert is_upload_endpoint("http://h/profile") is False


def test_upload_accepted() -> None:
    assert upload_accepted(200, "File uploaded to /uploads/orthrus_test.php", "orthrus_test.php") is True
    assert upload_accepted(200, "Invalid file type: only images allowed", "orthrus_test.php") is False
    assert upload_accepted(403, "ok", "orthrus_test.php") is False


class FakeResp:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text


def _ctx(http: object, endpoints: list[str]) -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(target="http://h/"),
        endpoints=[SimpleNamespace(url=u, params=[]) for u in endpoints],
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        http=http,
    )


class AcceptHttp:
    async def post(self, url: str, files: dict | None = None, **kw: object) -> FakeResp:
        fname = files["file"][0] if files else "?"
        return FakeResp(200, f"File uploaded to /uploads/{fname}")


class RejectHttp:
    async def post(self, url: str, files: dict | None = None, **kw: object) -> FakeResp:
        return FakeResp(200, "Invalid file type: only images are allowed")


async def test_scanner_flags_unrestricted_upload() -> None:
    findings = [f async for f in FileUploadScanner().scan(_ctx(AcceptHttp(), ["http://h/upload"]))]
    fu = [f for f in findings if f.vuln_type == "file-upload"]
    assert len(fu) == 1
    assert fu[0].severity == Severity.HIGH
    assert fu[0].cwe == "CWE-434"


async def test_scanner_quiet_when_rejected() -> None:
    findings = [f async for f in FileUploadScanner().scan(_ctx(RejectHttp(), ["http://h/upload"]))]
    assert [f for f in findings if f.vuln_type == "file-upload"] == []


async def test_scanner_skips_non_upload_endpoints() -> None:
    findings = [f async for f in FileUploadScanner().scan(_ctx(AcceptHttp(), ["http://h/profile"]))]
    assert [f for f in findings if f.vuln_type == "file-upload"] == []
