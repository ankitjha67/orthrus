"""Capture->Endpoint conversion for the browser-driven dynamic crawl."""

from __future__ import annotations

from orthrus.core.browser import CapturedRequest
from orthrus.core.schemas import HttpMethod, ParamLocation
from orthrus.recon.browser_crawl import endpoint_from_capture


def test_json_body_becomes_json_params():
    cap = CapturedRequest(
        method="POST",
        url="http://h/rest/user/login",
        post_data='{"email":"x","password":"y"}',
        content_type="application/json",
    )
    ep = endpoint_from_capture(cap)
    assert ep is not None
    assert ep.method == HttpMethod.POST
    assert ep.url == "http://h/rest/user/login"
    assert {(p.name, p.location) for p in ep.params} == {
        ("email", ParamLocation.JSON),
        ("password", ParamLocation.JSON),
    }


def test_query_string_becomes_query_params():
    cap = CapturedRequest(
        method="GET",
        url="http://h/rest/products/search?q=apple",
        resource_type="xhr",
    )
    ep = endpoint_from_capture(cap)
    assert ep is not None
    assert ep.method == HttpMethod.GET
    assert [(p.name, p.location, p.value) for p in ep.params] == [
        ("q", ParamLocation.QUERY, "apple")
    ]


def test_form_body_becomes_body_params():
    cap = CapturedRequest(
        method="POST",
        url="http://h/login",
        post_data="user=a&pass=b",
        content_type="application/x-www-form-urlencoded",
    )
    ep = endpoint_from_capture(cap)
    assert ep is not None
    assert {(p.name, p.location) for p in ep.params} == {
        ("user", ParamLocation.BODY),
        ("pass", ParamLocation.BODY),
    }


def test_nested_json_value_is_stringified():
    cap = CapturedRequest(
        method="POST",
        url="http://h/api/x",
        post_data='{"filter":{"a":1},"name":"z"}',
        content_type="application/json",
    )
    ep = endpoint_from_capture(cap)
    assert ep is not None
    by_name = {p.name: (p.location, p.value) for p in ep.params}
    assert by_name["name"] == (ParamLocation.JSON, "z")
    assert by_name["filter"][0] == ParamLocation.JSON
    assert by_name["filter"][1] == '{"a": 1}'


def test_unknown_method_returns_none():
    assert endpoint_from_capture(CapturedRequest(method="WEIRD", url="http://h/x")) is None


def test_socketio_transport_noise_is_dropped():
    # Engine.IO/Socket.IO polling is transport noise, not an app endpoint — and
    # caused a false-positive IDOR on its numeric EIO protocol-version param.
    cap = CapturedRequest(
        method="GET", url="http://h/socket.io/?EIO=4&transport=polling", resource_type="xhr"
    )
    assert endpoint_from_capture(cap) is None
    nested = CapturedRequest(method="GET", url="http://h/2/socket.io/?EIO=4", resource_type="xhr")
    assert endpoint_from_capture(nested) is None
