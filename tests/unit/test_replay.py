"""Tests for the confirmation-replay helpers (GET + POST-body reissue)."""

from __future__ import annotations

from types import SimpleNamespace

from hydra.core.schemas import (
    Endpoint,
    Evidence,
    Finding,
    HttpMethod,
    Param,
    ParamLocation,
    Severity,
)
from hydra.exploits._replay import find_endpoint, payload_from_evidence, reissue


def _finding(**kw: object) -> Finding:
    base: dict = {
        "vuln_type": "sqli",
        "title": "t",
        "severity": Severity.HIGH,
        "url": "http://h/x",
    }
    base.update(kw)
    return Finding(**base)


class FakeHttp:
    """Records the request reissue() makes; returns a kind-tagged sentinel."""

    def __init__(self) -> None:
        self.get_calls: list[tuple[str, bool]] = []
        self.post_calls: list[tuple[str, dict | None, bool]] = []

    async def get(self, url: str, *, follow_redirects: bool = True) -> SimpleNamespace:
        self.get_calls.append((url, follow_redirects))
        return SimpleNamespace(kind="get")

    async def post(
        self,
        url: str,
        *,
        data: dict | None = None,
        content: bytes | None = None,
        headers: dict | None = None,
        follow_redirects: bool = True,
    ) -> SimpleNamespace:
        self.post_calls.append((url, data, follow_redirects))
        return SimpleNamespace(kind="post")


# --- payload_from_evidence ---


def test_payload_recovered_after_first_equals():
    f = _finding(evidence=Evidence(request_raw="id=PAYLOAD"))
    assert payload_from_evidence(f) == "PAYLOAD"


def test_payload_keeps_equals_inside_payload():
    f = _finding(evidence=Evidence(request_raw="id=' OR '1'='1"))
    assert payload_from_evidence(f) == "' OR '1'='1"


def test_payload_none_without_equals():
    assert payload_from_evidence(_finding(evidence=Evidence(request_raw="noequals"))) is None


def test_payload_none_without_request_raw():
    assert payload_from_evidence(_finding()) is None


# --- find_endpoint ---


def test_find_endpoint_matches_url():
    ep = Endpoint(url="http://h/x", method=HttpMethod.POST)
    ctx = SimpleNamespace(endpoints=[ep])
    assert find_endpoint(ctx, "http://h/x") is ep


def test_find_endpoint_missing_returns_none():
    assert find_endpoint(SimpleNamespace(endpoints=[]), "http://h/x") is None


# --- reissue ---


async def test_reissue_get_replays_finding_url():
    http = FakeHttp()
    ctx = SimpleNamespace(http=http, endpoints=[])
    f = _finding(url="http://h/x?id=PAYLOAD", parameter="id", param_location=ParamLocation.QUERY)
    resp = await reissue(ctx, f)
    assert resp.kind == "get"
    assert http.get_calls == [("http://h/x?id=PAYLOAD", True)]
    assert http.post_calls == []


async def test_reissue_get_propagates_follow_redirects():
    http = FakeHttp()
    ctx = SimpleNamespace(http=http, endpoints=[])
    f = _finding(url="http://h/r?u=evil", param_location=ParamLocation.QUERY)
    await reissue(ctx, f, follow_redirects=False)
    assert http.get_calls == [("http://h/r?u=evil", False)]


async def test_reissue_body_rebuilds_form_with_recorded_payload():
    http = FakeHttp()
    ep = Endpoint(
        url="http://h/c",
        method=HttpMethod.POST,
        params=[
            Param(name="text", location=ParamLocation.BODY),
            Param(name="email", location=ParamLocation.BODY, value="a@b.c"),
        ],
    )
    ctx = SimpleNamespace(http=http, endpoints=[ep])
    f = _finding(
        url="http://h/c",
        parameter="text",
        param_location=ParamLocation.BODY,
        evidence=Evidence(request_raw="text=<script>"),
    )
    resp = await reissue(ctx, f)
    assert resp.kind == "post"
    url, data, _ = http.post_calls[0]
    assert url == "http://h/c"
    assert data == {"text": "<script>", "email": "a@b.c"}


async def test_reissue_body_fills_other_fields_with_default():
    http = FakeHttp()
    ep = Endpoint(
        url="http://h/c",
        method=HttpMethod.POST,
        params=[
            Param(name="a", location=ParamLocation.BODY),
            Param(name="b", location=ParamLocation.BODY),
        ],
    )
    ctx = SimpleNamespace(http=http, endpoints=[ep])
    f = _finding(
        url="http://h/c",
        parameter="a",
        param_location=ParamLocation.BODY,
        evidence=Evidence(request_raw="a=PAY"),
    )
    await reissue(ctx, f)
    _, data, _ = http.post_calls[0]
    assert data == {"a": "PAY", "b": "1"}


async def test_reissue_body_none_when_endpoint_missing():
    http = FakeHttp()
    ctx = SimpleNamespace(http=http, endpoints=[])
    f = _finding(
        url="http://h/c",
        parameter="text",
        param_location=ParamLocation.BODY,
        evidence=Evidence(request_raw="text=x"),
    )
    assert await reissue(ctx, f) is None
    assert http.post_calls == []


async def test_reissue_body_none_when_payload_unrecoverable():
    http = FakeHttp()
    ep = Endpoint(url="http://h/c", method=HttpMethod.POST,
                  params=[Param(name="text", location=ParamLocation.BODY)])
    ctx = SimpleNamespace(http=http, endpoints=[ep])
    f = _finding(
        url="http://h/c",
        parameter="text",
        param_location=ParamLocation.BODY,
        evidence=Evidence(request_raw="noequals"),
    )
    assert await reissue(ctx, f) is None
    assert http.post_calls == []
