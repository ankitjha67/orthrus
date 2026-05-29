"""Tests for the XXE payload construction (detection reuses LFI signatures)
plus the blind/out-of-band XXE flow against a fake OOB collaborator."""

from __future__ import annotations

from orthrus.core.callback import Interaction
from orthrus.scanners.xxe import XxeScanner, oob_xxe_payloads, xxe_payloads


def test_payloads_declare_external_entities():
    payloads = xxe_payloads()
    assert payloads
    for p in payloads:
        assert "<!ENTITY" in p
        assert "SYSTEM" in p
        assert "&xxe;" in p


def test_payloads_cover_unix_and_windows():
    joined = " ".join(xxe_payloads())
    assert "/etc/passwd" in joined
    assert "win.ini" in joined


def test_oob_payloads_embed_callback_and_entities():
    cb = "http://abc123.oast.test"
    payloads = oob_xxe_payloads(cb)
    assert len(payloads) == 2
    for p in payloads:
        assert cb in p
        assert "<!ENTITY" in p and "SYSTEM" in p
    # One general entity, one parameter (OOB-during-DTD) entity.
    assert any("&xxe;" in p for p in payloads)
    assert any("% ext" in p for p in payloads)


# ----------------------------------------------------------- blind/OOB fakes
class _Resp:
    status_code = 200
    text = ""


class _Http:
    def __init__(self) -> None:
        self.posts: list[tuple[str, bytes]] = []

    async def post(self, url, content=None, headers=None) -> _Resp:
        self.posts.append((url, content))
        return _Resp()


class _Scope:
    def is_allowed(self, url: str) -> bool:
        return True


class _Callback:
    def __init__(self, hit_for: str | None) -> None:
        self._n = 0
        self.hit_for = hit_for

    def new_token(self) -> tuple[str, str]:
        self._n += 1
        token = f"tok{self._n}"
        return token, f"http://cb.test/{token}"

    async def poll(self, token: str) -> list[Interaction]:
        if token == self.hit_for:
            return [Interaction(token=token, protocol="http", source_ip="10.0.0.5",
                                method="GET", path="/", body="GET / HTTP/1.1")]
        return []


class _Store:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    async def add_callback(self, *args, **kwargs) -> None:
        self.calls.append((args, kwargs))


class _Config:
    target = "http://target.test/api"


class _Ctx:
    def __init__(self, callback) -> None:
        self.config = _Config()
        self.endpoints: list = []
        self.scope = _Scope()
        self.http = _Http()
        self.callback = callback
        self.store = _Store()


async def test_oob_xxe_reports_blind_finding(monkeypatch):
    monkeypatch.setattr("orthrus.scanners.xxe.OOB_POLL_DELAY", 0)
    ctx = _Ctx(_Callback(hit_for="tok1"))  # the target gets the first token
    findings = [f async for f in XxeScanner().scan(ctx)]
    blind = [f for f in findings if "out-of-band" in f.title]
    assert len(blind) == 1
    assert blind[0].vuln_type == "xxe"
    assert blind[0].cwe == "CWE-611"
    assert blind[0].severity.value == "high"
    assert ctx.store.calls, "the OOB hit should be persisted via add_callback"
    # Both OOB payloads were delivered to the target.
    sent = b" ".join(c for _, c in ctx.http.posts if c)
    assert b"<!ENTITY xxe SYSTEM" in sent and b"% ext SYSTEM" in sent


async def test_oob_xxe_silent_without_hit(monkeypatch):
    monkeypatch.setattr("orthrus.scanners.xxe.OOB_POLL_DELAY", 0)
    ctx = _Ctx(_Callback(hit_for=None))  # no callback ever fires
    findings = [f async for f in XxeScanner().scan(ctx)]
    assert [f for f in findings if "out-of-band" in f.title] == []


async def test_oob_xxe_skipped_without_callback():
    ctx = _Ctx(None)
    findings = [f async for f in XxeScanner().scan(ctx)]
    assert findings == []
