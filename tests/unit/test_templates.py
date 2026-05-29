"""Declarative template engine: schema parsing, matchers, loader, URL render."""

from __future__ import annotations

import json

import pytest

from orthrus.templates.loader import load_templates
from orthrus.templates.matchers import (
    MatchInput,
    eval_matcher,
    eval_request_matchers,
    run_extractors,
)
from orthrus.templates.scanner import render
from orthrus.templates.schema import Matcher, Template


# ----------------------------------------------------------------- MatchInput
def _resp(status=200, body="", headers="") -> MatchInput:
    return MatchInput(status=status, body=body, headers=headers)


def test_status_matcher():
    m = Matcher(type="status", status=[200, 204])
    assert eval_matcher(m, _resp(status=200))[0] is True
    assert eval_matcher(m, _resp(status=404))[0] is False


def test_word_matcher_or_and_conditions():
    data = _resp(body="hello world")
    assert eval_matcher(Matcher(type="word", words=["hello", "nope"], condition="or"), data)[0]
    assert not eval_matcher(Matcher(type="word", words=["hello", "nope"], condition="and"), data)[0]
    assert eval_matcher(Matcher(type="word", words=["hello", "world"], condition="and"), data)[0]


def test_word_matcher_returns_matched_strings():
    data = _resp(body="DB_HOST=localhost")
    ok, strings = eval_matcher(Matcher(type="word", words=["DB_HOST", "x"]), data)
    assert ok is True
    assert "DB_HOST" in strings


def test_word_matcher_case_insensitive():
    data = _resp(headers="access-control-allow-origin: https://evil.example\n")
    m = Matcher(
        type="word", part="header", words=["Access-Control-Allow-Origin"], case_insensitive=True
    )
    assert eval_matcher(m, data)[0] is True


def test_word_matcher_part_header_vs_body():
    data = _resp(body="in body", headers="server: nginx\n")
    assert eval_matcher(Matcher(type="word", part="header", words=["nginx"]), data)[0]
    assert not eval_matcher(Matcher(type="word", part="body", words=["nginx"]), data)[0]


def test_regex_matcher_and_negative():
    data = _resp(body="version 1.2.3")
    assert eval_matcher(Matcher(type="regex", regex=[r"\d+\.\d+\.\d+"]), data)[0] is True
    neg = Matcher(type="regex", regex=[r"\d+\.\d+\.\d+"], negative=True)
    assert eval_matcher(neg, data)[0] is False


def test_regex_matcher_invalid_pattern_is_safe():
    data = _resp(body="x")
    assert eval_matcher(Matcher(type="regex", regex=["([unclosed"]), data)[0] is False


def test_size_matcher():
    data = _resp(body="abcde")
    assert eval_matcher(Matcher(type="size", size=[5]), data)[0] is True
    assert eval_matcher(Matcher(type="size", size=[10]), data)[0] is False


def test_unknown_matcher_type_never_matches():
    assert eval_matcher(Matcher(type="dsl"), _resp())[0] is False


# --------------------------------------------------- request-level matching
def test_request_matchers_condition_and():
    tpl = Template.from_dict(
        {
            "id": "t1",
            "requests": [
                {
                    "matchers-condition": "and",
                    "matchers": [
                        {"type": "status", "status": [200]},
                        {"type": "word", "words": ["secret"]},
                    ],
                }
            ],
        }
    )
    req = tpl.requests[0]
    assert eval_request_matchers(req, _resp(status=200, body="a secret here"))[0] is True
    assert eval_request_matchers(req, _resp(status=200, body="nothing"))[0] is False
    assert eval_request_matchers(req, _resp(status=500, body="a secret here"))[0] is False


def test_request_no_matchers_is_false():
    req = Template.from_dict({"id": "t", "requests": [{}]}).requests[0]
    assert eval_request_matchers(req, _resp())[0] is False


# ----------------------------------------------------------------- extractors
def test_regex_extractor_named_group():
    data = _resp(body="SECRET_KEY=abc123\nDB=postgres")
    extractors = Template.from_dict(
        {
            "id": "t",
            "requests": [
                {
                    "extractors": [
                        {"type": "regex", "name": "key", "regex": ["SECRET_KEY=(\\w+)"], "group": 1}
                    ]
                }
            ],
        }
    ).requests[0].extractors
    out = run_extractors(extractors, data)
    assert out["key"] == "abc123"


def test_kval_extractor_from_headers():
    data = _resp(headers="Server: nginx/1.25\nX-Powered-By: PHP/8.2\n")
    extractors = Template.from_dict(
        {"id": "t", "requests": [{"extractors": [{"type": "kval", "kval": ["Server"]}]}]}
    ).requests[0].extractors
    out = run_extractors(extractors, data)
    assert out["Server"] == "nginx/1.25"


# ------------------------------------------------------------ schema aliases
def test_template_accepts_http_key_alias():
    tpl = Template.from_dict({"id": "t", "http": [{"method": "POST", "path": ["{{BaseURL}}/x"]}]})
    assert tpl.requests[0].method == "POST"
    assert tpl.requests[0].path == ["{{BaseURL}}/x"]


def test_template_severity_and_tags_parsed():
    tpl = Template.from_dict(
        {"id": "t", "info": {"name": "X", "severity": "high", "tags": ["exposure", "config"]}}
    )
    assert tpl.info.severity.value == "high"
    assert tpl.info.primary_tag == "exposure"


# --------------------------------------------------------------- URL render
def test_render_baseurl_and_hostname():
    assert render("{{BaseURL}}/.env", "http://h:8080/path") == "http://h:8080/.env"
    assert render("{{Hostname}}", "http://h:8080/") == "h:8080"
    assert render("{{Host}}", "http://h:8080/") == "h"


def test_render_bare_absolute_path_gets_base_prepended():
    assert render("/.git/HEAD", "https://x.test/") == "https://x.test/.git/HEAD"


# --------------------------------------------------------------- loader
def test_load_builtin_templates():
    templates = load_templates("builtin")
    ids = {t.id for t in templates}
    assert "exposed-env-file" in ids
    assert "git-head-exposure" in ids
    # every builtin parses with at least one request and a matcher
    for t in templates:
        assert t.requests
        assert any(r.matchers for r in t.requests)


def test_load_single_json_template_file(tmp_path):
    p = tmp_path / "t.json"
    p.write_text(
        json.dumps(
            {
                "id": "json-tpl",
                "info": {"name": "JSON", "severity": "low"},
                "requests": [{"path": ["{{BaseURL}}/x"], "matchers": [{"type": "status", "status": [200]}]}],
            }
        ),
        encoding="utf-8",
    )
    templates = load_templates(str(p))
    assert len(templates) == 1
    assert templates[0].id == "json-tpl"


def test_load_directory_skips_invalid(tmp_path):
    (tmp_path / "good.json").write_text(
        json.dumps({"id": "good", "requests": [{"matchers": [{"type": "status", "status": [200]}]}]}),
        encoding="utf-8",
    )
    (tmp_path / "bad.json").write_text(json.dumps({"no_id": True}), encoding="utf-8")
    templates = load_templates(str(tmp_path))
    assert [t.id for t in templates] == ["good"]


def test_load_missing_path_raises():
    with pytest.raises(FileNotFoundError):
        load_templates("/no/such/templates/dir")
