"""JSON-body injection support in the shared injection plumbing."""

from __future__ import annotations

from types import SimpleNamespace

from hydra.core.schemas import Endpoint, HttpMethod, Param, ParamLocation
from hydra.scanners._injection import injection_points, send, used_url


class FakeResp:
    def __init__(self, kind: str) -> None:
        self.kind = kind


class FakeHttp:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict]] = []

    async def request(self, method: str, url: str, **kwargs: object) -> FakeResp:
        self.calls.append((method, url, kwargs))
        return FakeResp("req")


def _ctx(endpoints: list[Endpoint], http: FakeHttp | None = None) -> SimpleNamespace:
    return SimpleNamespace(endpoints=endpoints, http=http or FakeHttp())


def test_json_params_injectable_on_post():
    ep = Endpoint(
        url="http://h/rest/user/login",
        method=HttpMethod.POST,
        params=[
            Param(name="email", location=ParamLocation.JSON),
            Param(name="password", location=ParamLocation.JSON),
        ],
    )
    pts = list(injection_points(_ctx([ep])))
    assert {(p.param, p.location) for p in pts} == {
        ("email", ParamLocation.JSON),
        ("password", ParamLocation.JSON),
    }
    assert all(p.method == HttpMethod.POST for p in pts)


def test_json_params_skipped_on_get_but_query_kept():
    ep = Endpoint(
        url="http://h/x",
        method=HttpMethod.GET,
        params=[
            Param(name="a", location=ParamLocation.JSON),
            Param(name="q", location=ParamLocation.QUERY),
        ],
    )
    pts = list(injection_points(_ctx([ep])))
    assert {(p.param, p.location) for p in pts} == {("q", ParamLocation.QUERY)}


def test_json_param_injectable_on_put():
    ep = Endpoint(
        url="http://h/api/Users/1",
        method=HttpMethod.PUT,
        params=[Param(name="role", location=ParamLocation.JSON)],
    )
    pts = list(injection_points(_ctx([ep])))
    assert len(pts) == 1
    assert pts[0].method == HttpMethod.PUT
    assert pts[0].location == ParamLocation.JSON


async def test_send_json_builds_body_with_endpoint_method():
    http = FakeHttp()
    ep = Endpoint(
        url="http://h/rest/user/login",
        method=HttpMethod.POST,
        params=[
            Param(name="email", location=ParamLocation.JSON, value="a@b.c"),
            Param(name="password", location=ParamLocation.JSON, value="pw"),
        ],
    )
    ctx = _ctx([ep], http)
    point = next(p for p in injection_points(ctx) if p.param == "email")
    await send(ctx, point, "' OR 1=1--")
    method, url, kwargs = http.calls[0]
    assert method == "POST"
    assert url == "http://h/rest/user/login"
    assert kwargs["json"] == {"email": "' OR 1=1--", "password": "pw"}
    assert used_url(point, "x") == "http://h/rest/user/login"


async def test_send_query_mutates_url_no_body():
    http = FakeHttp()
    ep = Endpoint(
        url="http://h/s?q=x",
        method=HttpMethod.GET,
        params=[Param(name="q", location=ParamLocation.QUERY, value="x")],
    )
    ctx = _ctx([ep], http)
    point = next(iter(injection_points(ctx)))
    await send(ctx, point, "PAY")
    method, url, kwargs = http.calls[0]
    assert method == "GET"
    assert "q=PAY" in url
    assert "json" not in kwargs and "data" not in kwargs
