"""Second-order / planted-payload registry: plant -> detonate elsewhere -> correlate."""

from __future__ import annotations

from types import SimpleNamespace

from orthrus.core.schemas import (
    Confidence,
    Endpoint,
    HttpMethod,
    Param,
    ParamLocation,
    Severity,
)
from orthrus.core.second_order import (
    PlantedPayload,
    SecondOrderRegistry,
    build_payload,
    correlate,
)


# ------------------------------------------------------------ pure helpers
def test_build_payload_oob_and_marker_only():
    oob = build_payload("MARK1", "http://cb/tok1")
    assert "http://cb/tok1" in oob and "MARK1" in oob and oob.startswith('"><img')
    assert build_payload("MARK1", "") == "MARK1<!--orthrus-so-->"


def _plant(token: str, marker: str, sink: str = "http://t/profile") -> PlantedPayload:
    return PlantedPayload(token=token, marker=marker, sink_url=sink, sink_param="bio",
                          payload="x", callback_url="")


def test_correlate_oob_and_reflection_and_dedup():
    planted = {"t1": _plant("t1", "M1"), "t2": _plant("t2", "M2", "http://t/ticket")}
    interactions = {"t1": [SimpleNamespace(source_ip="10.0.0.9", protocol="http")]}
    observations = [("http://t/admin", "M2"), ("http://t/admin", "M2"),   # dup -> one hit
                    ("http://t/profile", "M1")]                            # same sink -> ignored
    hits = correlate(planted, interactions, observations)
    kinds = {(h.detonation, h.planted.token) for h in hits}
    assert ("oob-callback", "t1") in kinds
    assert ("reflected-elsewhere", "t2") in kinds
    assert len(hits) == 2                                                   # dup + same-sink dropped


def test_correlate_ignores_unknown_token_and_empty_interactions():
    planted = {"t1": _plant("t1", "M1")}
    assert correlate(planted, {"ghost": [SimpleNamespace()]}, []) == []
    assert correlate(planted, {"t1": []}, []) == []


# ------------------------------------------------------------ registry + observe
def test_plant_embeds_marker_and_observe_elsewhere_only():
    reg = SecondOrderRegistry(callback=None)
    p = reg.plant("http://t/profile", "bio")
    assert p.marker in p.payload
    reg.observe("http://t/admin/users", f"<td>{p.marker}</td>")   # elsewhere
    reg.observe("http://t/profile", f"<td>{p.marker}</td>")       # same sink -> ignored
    assert reg._observations == [("http://t/admin/users", p.marker)]


# ------------------------------------------------------------ fakes for plant/harvest
class _Resp:
    def __init__(self, status: int, text: str) -> None:
        self.status_code = status
        self.text = text


class _Http:
    def __init__(self) -> None:
        self.reflect: dict[str, str] = {}
        self.posts: list = []

    async def post(self, url, *, data=None, follow_redirects=False) -> _Resp:
        self.posts.append((url, data))
        return _Resp(200, "stored")

    async def get(self, url, *, follow_redirects=True) -> _Resp:
        return _Resp(200, self.reflect.get(url, "clean page"))


class _Callback:
    def __init__(self, fire: set[str]) -> None:
        self._n = 0
        self._fire = fire
        self.minted: list[str] = []

    def new_token(self):
        self._n += 1
        tok = f"tok{self._n}"
        self.minted.append(tok)
        return tok, f"http://cb/{tok}"

    async def poll(self, token: str) -> list:
        return [SimpleNamespace(source_ip="10.0.0.9", protocol="http")] if token in self._fire else []


def _ctx(http: _Http, callback=None, target: str = "http://t/") -> SimpleNamespace:
    ep = Endpoint(url="http://t/profile", method=HttpMethod.POST, source="form",
                  params=[Param(name="bio", location=ParamLocation.BODY, value="")])
    reg = SecondOrderRegistry(callback=callback)
    return SimpleNamespace(endpoints=[ep], http=http, config=SimpleNamespace(target=target),
                           scope=SimpleNamespace(is_allowed=lambda _u: True), second_order=reg)


async def test_plant_writable_forms_submits_the_canary():
    http = _Http()
    ctx = _ctx(http)
    planted = await ctx.second_order.plant_writable_forms(ctx)
    assert planted == 1 and len(http.posts) == 1
    url, data = http.posts[0]
    assert url == "http://t/profile" and ctx.second_order.planted[0].payload in data.values()


async def test_harvest_oob_callback_is_confirmed_high():
    http = _Http()
    cb = _Callback(fire={"tok1"})                 # the first planted canary "fires" in a console
    ctx = _ctx(http, callback=cb)
    await ctx.second_order.plant_writable_forms(ctx)
    findings = await ctx.second_order.harvest(ctx)
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "second-order-injection" and f.cwe == "CWE-79"
    assert f.severity == Severity.HIGH and f.confidence == Confidence.CONFIRMED
    assert "out of band" in f.description.lower() and "10.0.0.9" in (f.evidence.notes or "")


async def test_harvest_reflection_elsewhere_is_firm_medium():
    http = _Http()
    ctx = _ctx(http)                              # no callback -> reflection path only
    await ctx.second_order.plant_writable_forms(ctx)
    marker = ctx.second_order.planted[0].marker
    http.reflect["http://t/"] = f"<div>welcome {marker}</div>"   # reflected on the homepage
    findings = await ctx.second_order.harvest(ctx)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.MEDIUM and f.confidence == Confidence.FIRM
    assert f.url == "http://t/" and "reflected" in (f.evidence.notes or "")
