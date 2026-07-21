"""External-tool adapters: dalfox (XSS) + testssl.sh (TLS) parsers + registration."""

from __future__ import annotations

import orthrus.integrations  # noqa: F401  (registers the built-in adapters)
from orthrus.core.schemas import Confidence, Severity
from orthrus.integrations.base import TOOL_REGISTRY
from orthrus.integrations.checkov import parse_checkov_json
from orthrus.integrations.dalfox import parse_dalfox_json
from orthrus.integrations.ffuf import parse_ffuf_json
from orthrus.integrations.nikto import parse_nikto_json
from orthrus.integrations.semgrep import parse_semgrep_json
from orthrus.integrations.slither import parse_slither_json
from orthrus.integrations.testssl import parse_testssl_json
from orthrus.integrations.wpscan import parse_wpscan_json


def test_adapters_registered():
    for name in ("nuclei", "dalfox", "testssl", "ffuf", "nikto", "wpscan",
                 "slither", "checkov", "semgrep"):
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


NIKTO = """[
  {"host":"https://x.test","vulnerabilities":[
    {"id":"1","method":"GET","url":"/admin/","msg":"Directory indexing found."},
    {"id":"2","method":"GET","url":"/?q=1","msg":"Possible SQL Injection in parameter q."},
    {"id":"3","method":"GET","url":"/","msg":"The X-Frame-Options header is not present."}
  ]}
]"""


def test_nikto_classifies_and_rates():
    findings = parse_nikto_json(NIKTO, "https://x.test")
    assert len(findings) == 3
    by_type = {f.vuln_type: f for f in findings}
    assert by_type["directory-listing"].severity == Severity.LOW
    assert by_type["sqli"].severity == Severity.MEDIUM         # injection keyword -> promoted
    assert by_type["security-headers"].severity == Severity.INFO
    assert by_type["sqli"].url == "https://x.test/?q=1"        # relative path joined to host
    assert all(f.scanner == "nikto" for f in findings)
    assert parse_nikto_json("not json", "https://x.test") == []


WPSCAN = """{
  "target_url":"https://wp.test/",
  "version":{"number":"5.2","vulnerabilities":[
    {"title":"Core auth bypass","references":{"cve":["2019-1234"]},"fixed_in":"5.2.1"}]},
  "plugins":{"contact-form-7":{"slug":"contact-form-7",
    "vulnerabilities":[{"title":"Stored XSS","references":{},"fixed_in":"5.1.4"}]}},
  "interesting_findings":[
    {"url":"https://wp.test/wp-content/debug.log","type":"debug_log","to_s":"Debug log found"},
    {"url":"https://wp.test/","type":"headers","to_s":"Headers"}
  ]
}"""


def test_wpscan_maps_core_plugins_and_interesting():
    findings = parse_wpscan_json(WPSCAN, "https://wp.test")
    titles = [f.title for f in findings]
    # core vuln (has CVE -> HIGH), plugin vuln (no CVE -> MEDIUM), debug_log + headers interesting
    assert len(findings) == 4
    core = next(f for f in findings if "core" in f.title.lower())
    assert core.severity == Severity.HIGH and core.vuln_type == "vulnerable-component"
    assert "CVE-2019-1234" in core.description
    plugin = next(f for f in findings if "contact-form-7" in f.title)
    assert plugin.severity == Severity.MEDIUM
    debug = next(f for f in findings if f.vuln_type == "exposed-file")
    assert debug.severity == Severity.MEDIUM
    assert any("[wpscan]" in t for t in titles)
    assert parse_wpscan_json("nope", "https://wp.test") == []


SLITHER = """{"success":true,"results":{"detectors":[
  {"check":"reentrancy-eth","impact":"High","confidence":"Medium",
   "description":"Reentrancy in withdraw()",
   "elements":[{"source_mapping":{"filename_relative":"contracts/Bank.sol","lines":[42,43]}}]},
  {"check":"solc-version","impact":"Informational","confidence":"High",
   "description":"Old solc","elements":[]}
]}}"""


def test_slither_maps_detectors_and_ontology():
    findings = parse_slither_json(SLITHER, "contracts/")
    assert len(findings) == 2
    reent = next(f for f in findings if "reentrancy-eth" in f.title)
    assert reent.vuln_type == "reentrancy"                 # mapped to ontology class
    assert reent.severity == Severity.HIGH                 # impact High
    assert reent.confidence == Confidence.FIRM             # confidence Medium
    assert reent.url == "contracts/Bank.sol:42"            # first location file:line
    info = next(f for f in findings if "solc-version" in f.title)
    assert info.vuln_type == "smart-contract"              # unmapped -> default class
    assert info.url == "contracts/"                         # no elements -> falls back to target
    assert parse_slither_json("not json", "contracts/") == []


CHECKOV = """{"results":{"failed_checks":[
  {"check_id":"CKV_AWS_20","check_name":"S3 Bucket has an ACL defined which allows public READ access.",
   "severity":"HIGH","resource":"aws_s3_bucket.data","file_path":"/main.tf","file_line_range":[10,20],
   "guideline":"https://docs/ckv-aws-20"},
  {"check_id":"CKV_AWS_18","check_name":"Ensure S3 bucket has access logging enabled",
   "resource":"aws_s3_bucket.data","file_path":"/main.tf","file_line_range":[10,20]}
]}}"""


def test_checkov_maps_failed_checks():
    findings = parse_checkov_json(CHECKOV, "/infra")
    assert len(findings) == 2
    high = next(f for f in findings if "CKV_AWS_20" in f.evidence.notes)
    assert high.vuln_type == "cloud-misconfig" and high.severity == Severity.HIGH
    assert high.url == "/main.tf:10" and high.scanner == "checkov"
    # missing severity -> default MEDIUM
    other = next(f for f in findings if "CKV_AWS_18" in f.evidence.notes)
    assert other.severity == Severity.MEDIUM
    # list-of-reports shape also supported
    assert len(parse_checkov_json(f"[{CHECKOV}]", "/infra")) == 2
    assert parse_checkov_json("not json", "/infra") == []


SEMGREP = """{"results":[
  {"check_id":"python.lang.security.audit.dangerous-exec.dangerous-exec","path":"app/views.py",
   "start":{"line":12},"extra":{"severity":"ERROR","message":"Detected exec() with user input.",
   "metadata":{"cwe":["CWE-95: Improper Neutralization"]}}},
  {"check_id":"generic.secrets.hardcoded","path":"app/conf.py","start":{"line":3},
   "extra":{"severity":"WARNING","message":"Hardcoded secret","metadata":{}}}
]}"""


def test_semgrep_maps_results_and_cwe():
    findings = parse_semgrep_json(SEMGREP, "app/")
    assert len(findings) == 2
    err = next(f for f in findings if f.url == "app/views.py:12")
    assert err.vuln_type == "sast" and err.severity == Severity.HIGH   # ERROR -> HIGH
    assert err.title == "[semgrep] dangerous-exec"                     # last dotted segment
    assert err.cwe == "CWE-95: Improper Neutralization"
    warn = next(f for f in findings if f.url == "app/conf.py:3")
    assert warn.severity == Severity.MEDIUM and warn.cwe is None       # WARNING -> MEDIUM
    assert parse_semgrep_json("not json", "app/") == []
