"""External-tool orchestration framework + nuclei adapter."""

from __future__ import annotations

import json
from types import SimpleNamespace

from orthrus.core.schemas import Severity
from orthrus.integrations import TOOL_REGISTRY, available_tools, get_tools
from orthrus.integrations.base import ExternalToolAdapter
from orthrus.integrations.nuclei import NucleiAdapter, parse_nuclei_jsonl


# ----------------------------------------------------------------- registry
def test_nuclei_is_registered() -> None:
    assert "nuclei" in TOOL_REGISTRY
    assert isinstance(get_tools(["nuclei"])[0], NucleiAdapter)
    assert get_tools(["all"])  # 'all' selects every adapter
    assert get_tools(["does-not-exist"]) == []


def test_available_tools_reports_each() -> None:
    avail = available_tools()
    assert "nuclei" in avail
    assert isinstance(avail["nuclei"], bool)


def test_nuclei_command_targets_url_with_jsonl() -> None:
    cmd = NucleiAdapter().build_command("https://example.com")
    assert cmd[0] == "nuclei"
    assert "https://example.com" in cmd
    assert "-jsonl" in cmd


# ----------------------------------------------------------------- parser
def test_parse_nuclei_jsonl_maps_severity_and_fields() -> None:
    lines = [
        json.dumps(
            {
                "template-id": "CVE-2021-44228",
                "info": {
                    "name": "Apache Log4j RCE",
                    "severity": "critical",
                    "description": "Log4Shell",
                    "classification": {"cwe-id": ["CWE-502"]},
                },
                "matched-at": "https://example.com:8080/",
            }
        ),
        json.dumps(
            {
                "template-id": "tech-detect",
                "info": {"name": "nginx", "severity": "info"},
                "host": "https://example.com",
            }
        ),
        "not json — ignored",
        "",
    ]
    findings = parse_nuclei_jsonl("\n".join(lines), "https://example.com")
    assert len(findings) == 2
    crit = findings[0]
    assert crit.severity == Severity.CRITICAL
    assert crit.vuln_type == "tool-nuclei"
    assert crit.cwe == "CWE-502"
    assert "Log4j" in crit.title
    assert crit.url == "https://example.com:8080/"
    assert findings[1].severity == Severity.INFO


def test_parse_handles_empty_and_garbage() -> None:
    assert parse_nuclei_jsonl("", "t") == []
    assert parse_nuclei_jsonl("garbage\nlines\n", "t") == []


# ------------------------------------------------------- run() behavior
class _FakeScope:
    def __init__(self, allowed: bool) -> None:
        self._allowed = allowed

    def is_allowed(self, _url: str) -> bool:
        return self._allowed


def _ctx(allowed: bool = True) -> SimpleNamespace:
    return SimpleNamespace(config=SimpleNamespace(target="https://example.com"), scope=_FakeScope(allowed))


class _StubTool(ExternalToolAdapter):
    name = "stub"
    binary = "stub-binary-does-not-exist"

    def build_command(self, target: str) -> list[str]:
        return [self.binary, target]

    def parse_output(self, stdout: str, target: str):  # pragma: no cover - not reached
        return []


async def test_run_skips_when_binary_missing() -> None:
    # Binary absent -> run() returns [] without attempting a subprocess.
    assert await _StubTool().run(_ctx(allowed=True)) == []
