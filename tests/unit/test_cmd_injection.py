"""Tests for the command-injection detectors (output + out-of-band)."""

from __future__ import annotations

import re
from types import SimpleNamespace

from orthrus.core.schemas import Endpoint, HttpMethod, Param, ParamLocation
from orthrus.scanners import cmd_injection as ci
from orthrus.scanners.cmd_injection import CommandInjectionScanner, cmd_executed, cmd_oob_payloads

CANARY = "ORTHRUSDEADBEEF"


def test_canary_as_output_is_execution():
    assert cmd_executed(CANARY, f"<pre>{CANARY}\n</pre>") is True


def test_reflected_echo_command_is_not_execution():
    assert cmd_executed(CANARY, f"you sent: ; echo {CANARY}") is False


def test_absent_canary():
    assert cmd_executed(CANARY, "<html>nothing</html>") is False


# ----------------------------------------------------------------- OOB payloads
def test_cmd_oob_payloads_contain_url_and_separators():
    payloads = cmd_oob_payloads("1", "http://cb/tok1")
    joined = "\n".join(payloads)
    assert "http://cb/tok1" in joined
    assert any(p.startswith("1;curl ") for p in payloads)
    assert any(p.startswith("$(curl ") for p in payloads)
    assert any("wget" in p for p in payloads)


# ----------------------------------------------------------------- OOB scan flow
class _Resp:
    def __init__(self, text: str = "ok") -> None:
        self.text = text
        self.status_code = 200


class _Interaction:
    protocol = "http"
    source_ip = "203.0.113.9"
    method = "GET"
    path = "/"


class _FakeCallback:
    """Hands out tokens and records a hit when a payload 'executes' (calls back)."""

    def __init__(self) -> None:
        self._n = 0
        self.hits: dict[str, list[_Interaction]] = {}

    def new_token(self) -> tuple[str, str]:
        self._n += 1
        tok = f"tok{self._n}"
        return tok, f"http://cb/{tok}"

    def mark(self, token: str) -> None:
        self.hits.setdefault(token, [_Interaction()])

    async def poll(self, token: str) -> list[_Interaction]:
        return self.hits.get(token, [])


class _FakeStore:
    async def add_callback(self, *a: object, **k: object) -> int:
        return 1


async def test_oob_confirms_blind_command_injection(monkeypatch):
    cb = _FakeCallback()

    async def fake_send(ctx, point, payload):  # noqa: ANN001
        # Simulate a vulnerable shell: an injected curl to the callback "executes".
        m = re.search(r"http://cb/(tok\d+)", payload)
        if m:
            cb.mark(m.group(1))
        return _Resp()

    monkeypatch.setattr(ci, "send", fake_send)
    monkeypatch.setattr(ci.asyncio, "sleep", lambda _s: _noop())

    ep = Endpoint(
        url="http://h/run?host=x",
        method=HttpMethod.GET,
        params=[Param(name="host", location=ParamLocation.QUERY, value="x")],
    )
    ctx = SimpleNamespace(
        endpoints=[ep],
        http=SimpleNamespace(),
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(aggressiveness="normal"),
        callback=cb,
        store=_FakeStore(),
    )
    findings = [f async for f in CommandInjectionScanner().scan(ctx)]
    oob = [f for f in findings if "out-of-band" in f.title]
    assert len(oob) == 1
    assert oob[0].cwe == "CWE-78"
    assert oob[0].evidence.matched_at == "203.0.113.9"


async def test_no_oob_without_callback(monkeypatch):
    async def fake_send(ctx, point, payload):  # noqa: ANN001
        return _Resp()

    monkeypatch.setattr(ci, "send", fake_send)
    ep = Endpoint(
        url="http://h/run?host=x",
        method=HttpMethod.GET,
        params=[Param(name="host", location=ParamLocation.QUERY, value="x")],
    )
    ctx = SimpleNamespace(
        endpoints=[ep], http=SimpleNamespace(),
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(aggressiveness="normal"), callback=None, store=None,
    )
    assert [f async for f in CommandInjectionScanner().scan(ctx)] == []


async def _noop() -> None:
    return None
