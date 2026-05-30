"""Tests for the directory-listing / autoindex scanner.

Covers the pure marker detector (positive + negative cases), the candidate-URL
builder, and the scanner end-to-end against duck-typed fakes.
"""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import Severity
from orthrus.scanners.directory_listing import (
    DirectoryListingScanner,
    candidate_dirs,
    is_directory_listing,
)


# ------------------------------------------------------------- pure detectors
def test_is_directory_listing_positive_markers() -> None:
    assert is_directory_listing("<h1>Index of /uploads</h1>") is True
    assert is_directory_listing("<title>Index of /files</title>") is True
    assert is_directory_listing("Directory listing for /static/") is True
    assert is_directory_listing("[To Parent Directory]") is True
    assert is_directory_listing('<a href="../">Parent Directory</a>') is True


def test_is_directory_listing_case_insensitive() -> None:
    assert is_directory_listing("INDEX OF /BACKUP") is True
    assert is_directory_listing("DIRECTORY LISTING FOR /X") is True


def test_is_directory_listing_negative() -> None:
    assert is_directory_listing("<html><body>Welcome home</body></html>") is False
    assert is_directory_listing("404 not found") is False
    # "Parent Directory" text alone, without an anchor, is not enough.
    assert is_directory_listing("Go to the Parent Directory of the site") is False


def test_candidate_dirs_walks_parents_and_adds_common() -> None:
    dirs = candidate_dirs("http://h/", ["http://h/a/b/c.php"])
    assert "http://h/a/b/" in dirs
    assert "http://h/a/" in dirs
    # common list is appended for the target origin
    assert "http://h/uploads/" in dirs
    assert "http://h/" in dirs
    # de-duplicated
    assert len(dirs) == len(set(dirs))


# ------------------------------------------------------------ scanner harness
class FakeResp:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text
        self.headers: dict[str, str] = {}
        self.content_type: str | None = None


def _ctx(http: object, endpoints: list[object] | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(target="http://h/"),
        endpoints=endpoints or [],
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        http=http,
    )


class ListingHttp:
    """Serves an autoindex page at /uploads/, normal page everywhere else."""

    async def get(self, url: str, **kw: object) -> FakeResp:
        if url.endswith("/uploads/"):
            return FakeResp(
                200,
                "<html><head><title>Index of /uploads</title></head>"
                '<body><a href="../">Parent Directory</a></body></html>',
            )
        return FakeResp(200, "<html><body>home</body></html>")


class CleanHttp:
    async def get(self, url: str, **kw: object) -> FakeResp:
        return FakeResp(403, "<html><body>Forbidden</body></html>")


class MarkerButNot200Http:
    """Body has a listing marker but the status is not 200 -> must not flag."""

    async def get(self, url: str, **kw: object) -> FakeResp:
        return FakeResp(404, "<title>Index of /uploads</title>")


async def test_scanner_flags_autoindex() -> None:
    findings = [f async for f in DirectoryListingScanner().scan(_ctx(ListingHttp()))]
    dirlist = [f for f in findings if f.vuln_type == "directory-listing"]
    assert len(dirlist) == 1
    f = dirlist[0]
    assert f.severity == Severity.MEDIUM
    assert f.cwe == "CWE-548"
    assert f.title == "Directory listing enabled: /uploads/"
    assert f.evidence.matched_at == "autoindex"


async def test_scanner_quiet_when_no_listing() -> None:
    findings = [f async for f in DirectoryListingScanner().scan(_ctx(CleanHttp()))]
    assert [f for f in findings if f.vuln_type == "directory-listing"] == []


async def test_scanner_requires_200() -> None:
    findings = [f async for f in DirectoryListingScanner().scan(_ctx(MarkerButNot200Http()))]
    assert [f for f in findings if f.vuln_type == "directory-listing"] == []
