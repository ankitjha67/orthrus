"""Dependency-confusion scanner: manifest parsing + registry-claim check."""

from __future__ import annotations

import httpx

from orthrus.scanners.dependency_confusion import (
    _registry_url,
    is_scoped_npm,
    is_unclaimed,
    parse_package_json,
    parse_requirements,
)


def test_parse_package_json_all_groups():
    text = (
        '{"dependencies":{"react":"^18","@acme/ui":"1.0"},'
        '"devDependencies":{"jest":"29"},'
        '"peerDependencies":{"vue":"3"},"optionalDependencies":{"fsevents":"2"}}'
    )
    assert parse_package_json(text) == ["react", "@acme/ui", "jest", "vue", "fsevents"]


def test_parse_package_json_malformed():
    assert parse_package_json("not json") == []
    assert parse_package_json("[1,2,3]") == []


def test_parse_requirements():
    body = (
        "flask==2.0.1\n"
        "# a comment\n"
        "requests>=2.0\n"
        "-r dev-requirements.txt\n"
        "git+https://github.com/x/y\n"
        "Django[argon2]>=4.0 ; python_version>='3.8'\n"
        "\n"
        "internal-shared-lib\n"
    )
    assert parse_requirements(body) == ["flask", "requests", "django", "internal-shared-lib"]


def test_is_scoped_npm():
    assert is_scoped_npm("@acme/ui")
    assert not is_scoped_npm("react")
    assert not is_scoped_npm("@acme")  # no slash → not a scoped package spec


def test_registry_url_encoding():
    assert _registry_url("react", "npm") == "https://registry.npmjs.org/react"
    assert _registry_url("@acme/ui", "npm") == "https://registry.npmjs.org/@acme%2fui"
    assert _registry_url("flask", "pypi") == "https://pypi.org/pypi/flask/json"


def _client(status: int):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={} if status == 200 else None)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_is_unclaimed_404_is_claimable():
    async with _client(404) as c:
        assert await is_unclaimed(c, "internal-pkg", "npm") is True


async def test_is_unclaimed_200_is_claimed():
    async with _client(200) as c:
        assert await is_unclaimed(c, "react", "npm") is False


async def test_is_unclaimed_other_status_is_none():
    # 429/5xx must not be guessed as claimable (avoid false positives).
    async with _client(429) as c:
        assert await is_unclaimed(c, "react", "npm") is None
