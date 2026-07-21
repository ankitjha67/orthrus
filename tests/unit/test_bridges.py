"""Traffic bridges: Burp XML / Caido JSON / HAR parsers + graph fold (PRD §7.12)."""

from __future__ import annotations

import asyncio
import base64
import json

import pytest

from orthrus.bridges import (
    endpoint_juicy_score,
    fold_traffic,
    parse_burp_xml,
    parse_caido_json,
    parse_har,
)
from orthrus.bridges.base import CapturedRequest
from orthrus.bridges.burp import UnsafeXmlError
from orthrus.model.store import ProgramGraph


def _b64_request(body: str = "") -> str:
    raw = ("POST /login HTTP/1.1\r\nHost: shop.example.com\r\n"
           "Content-Type: application/x-www-form-urlencoded\r\n\r\n" + body)
    return base64.b64encode(raw.encode()).decode()


BURP = f"""<?xml version="1.0"?>
<!DOCTYPE items [
<!ELEMENT items (item*)>
<!ATTLIST items burpVersion CDATA "">
]>
<items burpVersion="2023.1">
  <item>
    <url><![CDATA[https://shop.example.com/login]]></url>
    <host ip="1.2.3.4">shop.example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method><![CDATA[POST]]></method>
    <path><![CDATA[/login]]></path>
    <request base64="true"><![CDATA[{_b64_request("username=admin&password=x")}]]></request>
    <status>200</status>
    <responselength>3123</responselength>
    <mimetype>HTML</mimetype>
  </item>
  <item>
    <url><![CDATA[https://shop.example.com/products?id=1&sort=name]]></url>
    <host ip="1.2.3.4">shop.example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method><![CDATA[GET]]></method>
    <path><![CDATA[/products?id=1&sort=name]]></path>
    <status>200</status>
    <responselength>900</responselength>
    <mimetype>JSON</mimetype>
  </item>
</items>"""


def test_burp_parses_tags_query_and_body_params():
    reqs = parse_burp_xml(BURP)
    assert len(reqs) == 2
    login = next(r for r in reqs if r.path == "/login")
    assert login.method == "POST" and login.host == "shop.example.com"
    assert login.body_params == ["password", "username"]     # mined from decoded request
    assert login.scheme == "https" and login.port == 443
    products = next(r for r in reqs if r.path == "/products")
    assert products.query_params == ["id", "sort"]           # query split off the path
    assert products.status == 200 and products.response_size == 900


def test_burp_refuses_xxe_and_tolerates_garbage():
    evil = ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
            '"file:///etc/passwd">]><items><item><host>x</host></item></items>')
    with pytest.raises(UnsafeXmlError):
        parse_burp_xml(evil)
    assert parse_burp_xml("not xml at all") == []
    assert parse_burp_xml("") == []


CAIDO = json.dumps([
    {"host": "api.example.com", "port": 443, "isTls": True, "method": "GET",
     "path": "/v1/users", "query": "page=2&limit=50",
     "response": {"statusCode": 200, "length": 2048, "mimetype": "application/json"}},
    {"host": "api.example.com", "port": 443, "isTls": False, "method": "PUT",
     "path": "/v1/users/7", "query": "",
     "body": '{"email":"a@b.c","role":"admin"}',
     "response": {"statusCode": 204}},
])


def test_caido_parses_array_shape():
    reqs = parse_caido_json(CAIDO)
    assert len(reqs) == 2
    get = next(r for r in reqs if r.method == "GET")
    assert get.host == "api.example.com" and get.query_params == ["limit", "page"]
    assert get.scheme == "https" and get.status == 200
    put = next(r for r in reqs if r.method == "PUT")
    assert put.scheme == "http"                              # isTls False
    assert put.body_params == ["email", "role"]              # JSON body keys


def test_caido_unwraps_graphql_envelope_and_tolerates_garbage():
    enveloped = json.dumps({"data": {"requests": {"edges": [
        {"node": {"host": "x.example.com", "method": "GET", "path": "/a", "query": "q=1"}}]}}})
    reqs = parse_caido_json(enveloped)
    assert len(reqs) == 1 and reqs[0].query_params == ["q"]
    assert parse_caido_json("nope") == []
    assert parse_caido_json("") == []


HAR = json.dumps({"log": {"version": "1.2", "entries": [
    {"request": {"method": "GET", "url": "https://www.example.com/search?q=x&lang=en",
                 "queryString": [{"name": "q", "value": "x"}, {"name": "lang", "value": "en"}]},
     "response": {"status": 200, "content": {"size": 512, "mimeType": "text/html"}}},
    {"request": {"method": "POST", "url": "https://www.example.com/api/comment",
                 "queryString": [],
                 "postData": {"mimeType": "application/x-www-form-urlencoded",
                              "params": [{"name": "body"}, {"name": "post_id"}]}},
     "response": {"status": 201, "content": {"size": 12, "mimeType": "application/json"}}},
]}})


def test_har_parses_query_and_postdata_params():
    reqs = parse_har(HAR)
    assert len(reqs) == 2
    search = next(r for r in reqs if r.path == "/search")
    assert search.query_params == ["lang", "q"] and search.host == "www.example.com"
    comment = next(r for r in reqs if r.path == "/api/comment")
    assert comment.method == "POST" and comment.body_params == ["body", "post_id"]
    assert comment.status == 201
    assert parse_har("not json") == [] and parse_har("") == []


def test_juicy_score_prioritizes_inputs_mutations_and_auth_surface():
    boring = CapturedRequest(method="GET", host="x", path="/static/logo.png")
    juicy = CapturedRequest(method="POST", host="x", path="/api/admin/login",
                            body_params=["u", "p"], content_type="application/json")
    assert endpoint_juicy_score(juicy) > endpoint_juicy_score(boring)
    assert endpoint_juicy_score(juicy) <= 1.0


def test_fold_traffic_into_graph_dedups_and_respects_scope(tmp_path):
    async def run():
        g = ProgramGraph(f"sqlite+aiosqlite:///{(tmp_path / 'b.db').as_posix()}")
        await g.init()
        pid = (await g.create_program("Acme", "self-owned-lab", platform="self")).id

        reqs = parse_caido_json(CAIDO) + [
            CapturedRequest(method="GET", host="cdn.thirdparty.io", path="/lib.js")]
        # scope: only *.example.com is in scope → third-party CDN refused
        res = await fold_traffic(g, pid, reqs, source="caido",
                                 in_scope=lambda h: h.endswith("example.com"))
        assert res.total == 3
        assert res.skipped_out_of_scope == 1                 # cdn.thirdparty.io dropped
        assert res.new_assets == 1                           # both example.com reqs share one host
        assert res.new_endpoints == 2
        assets = await g.list_assets(pid)
        assert [a.canonical_value for a in assets] == ["api.example.com"]
        eps = await g.list_endpoints(pid)
        assert {e.path for e in eps} == {"/v1/users", "/v1/users/7"}

        # re-folding the same session is idempotent (upsert, not duplicate)
        res2 = await fold_traffic(g, pid, reqs, source="caido",
                                  in_scope=lambda h: h.endswith("example.com"))
        assert res2.new_assets == 0 and res2.new_endpoints == 0
        assert res2.seen_endpoints == 2
        assert len(await g.list_endpoints(pid)) == 2
        await g.close()

    asyncio.run(run())
