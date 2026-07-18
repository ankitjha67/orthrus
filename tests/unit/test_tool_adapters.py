"""External-tool adapters: dalfox (XSS) + testssl.sh (TLS) parsers + registration."""

from __future__ import annotations

import orthrus.integrations  # noqa: F401  (registers the built-in adapters)
from orthrus.core.schemas import Confidence, Severity
from orthrus.integrations.base import TOOL_REGISTRY
from orthrus.integrations.dalfox import parse_dalfox_json
from orthrus.integrations.ffuf import parse_ffuf_json
from orthrus.integrations.testssl import parse_testssl_json


def test_adapters_registered():
    for name in ("nuclei", "dalfox", "testssl", "ffuf"):
        assert name in TOOL_REGISTRY


DALFOX = """[
  {"type":"V","severity":"High","cwe":"CWE-79","data":"https://x.test/?q=<script>alert(1)</script>",
   "evidence":"alert fired","message_str":"verified reflected XSS","param":"q"},
  {"type":"R","severity":"Medium","data":"https://x.test/?s=payload","message_str":"reflected"}
]"""


def test_dalfox_parses_pocs():
    findings = parse_dalfox_json(DALFOX, "https://x.test")
    assert len(findings) == 2
    a = findings[0]
    assert a.vuln_type == "xss" and a.severity == Severity.HIGH
    assert a.confidence == Confidence.CONFIRMED     # type 'V' = verified
    assert a.parameter == "q" and "<script>" in a.url
    assert findings[1].confidence == Confidence.FIRM  # type 'R' = reflected


def test_dalfox_handles_jsonlines_and_garbage():
    jsonl = '{"type":"V","severity":"High","data":"https://x/?a=1"}\nnot json\n'
    assert len(parse_dalfox_json(jsonl, "https://x")) == 1
    assert parse_dalfox_json("", "https://x") == []


TESTSSL = """[
  {"id":"heartbleed","severity":"CRITICAL","finding":"VULNERABLE (NOT ok)","cve":"CVE-2014-0160"},
  {"id":"cert_trust","severity":"OK","finding":"passed"},
  {"id":"BEAST","severity":"LOW","finding":"potentially VULNERABLE"},
  {"id":"scanTime","severity":"INFO","finding":"12s"}
]"""


def test_testssl_keeps_only_real_severities():
    findings = parse_testssl_json(TESTSSL, "example.com")
    ids = {f.title for f in findings}
    assert ids == {"[testssl] heartbleed", "[testssl] BEAST"}   # OK + INFO dropped
    crit = next(f for f in findings if "heartbleed" in f.title)
    assert crit.severity == Severity.CRITICAL and crit.vuln_type == "tls"
    assert crit.url == "https://example.com"


FFUF = ('{"results":[{"url":"http://x.test/admin","status":200,"length":1234},'
        '{"url":"http://x.test/old","status":301,"length":0},'
        '{"url":"http://x.test/secret","status":403,"length":9}]}')


def test_ffuf_parses_and_rates_paths():
    findings = parse_ffuf_json(FFUF, "http://x.test")
    assert len(findings) == 3
    by_url = {f.url: f for f in findings}
    assert by_url["http://x.test/admin"].severity == Severity.LOW    # 200 -> low
    assert by_url["http://x.test/secret"].severity == Severity.LOW   # 403 -> low
    assert by_url["http://x.test/old"].severity == Severity.INFO     # 301 -> info
    assert all(f.vuln_type == "content-discovery" for f in findings)
    assert parse_ffuf_json("not json", "http://x") == []
