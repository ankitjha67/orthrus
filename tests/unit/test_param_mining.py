"""Parameter-mining recon module."""

from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

from orthrus.core.schemas import Endpoint, HttpMethod, ParamLocation
from orthrus.recon.param_mining import ParameterMiner, reflected


def test_reflected() -> None:
    assert reflected("abc", "x abc y") is True
    assert reflected("abc", "nothing") is False


def _ctx(http: object, endpoints: list[Endpoint]) -> SimpleNamespace:
    return SimpleNamespace(
        endpoints=endpoints,
        http=http,
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(target="http://h/"),
    )


class FakeResp:
    def __init__(self, text: str) -> None:
        self.text = text


class HiddenParamHttp:
    """Reflects only the value of a 'debug' query param (a hidden parameter)."""

    async def get(self, url: str, **kw: object) -> FakeResp:
        qs = parse_qs(urlsplit(url).query)
        if "debug" in qs:
            return FakeResp(f"items (debug mode: {qs['debug'][0]})")
        return FakeResp("items list")


class EchoEverythingHttp:
    """Reflects every parameter value -> mining can't distinguish, yields nothing."""

    async def get(self, url: str, **kw: object) -> FakeResp:
        vals = " ".join(v[0] for v in parse_qs(urlsplit(url).query).values())
        return FakeResp(f"you sent {vals}")


async def test_discovers_hidden_param() -> None:
    ep = Endpoint(url="http://h/items", method=HttpMethod.GET, params=[])
    found = [e async for e in ParameterMiner().discover(_ctx(HiddenParamHttp(), [ep]))]
    names = {p.name for e in found for p in e.params}
    assert "debug" in names
    assert all(p.location == ParamLocation.QUERY for e in found for p in e.params)


async def test_skips_reflect_everything_endpoint() -> None:
    ep = Endpoint(url="http://h/echo", method=HttpMethod.GET, params=[])
    found = [e async for e in ParameterMiner().discover(_ctx(EchoEverythingHttp(), [ep]))]
    assert found == []  # baseline random param reflected -> endpoint skipped
