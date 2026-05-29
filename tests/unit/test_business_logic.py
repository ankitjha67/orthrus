"""Business-logic probes: parameter tampering + HTTP parameter pollution.

Covers the pure detection logic (low-false-positive by design) and drives the
scanner end-to-end against duck-typed fakes for the positive and negative paths.
"""

from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import parse_qsl, urlsplit

from orthrus.core.schemas import Endpoint, HttpMethod, Param, ParamLocation, Severity
from orthrus.scanners.business_logic import (
    CONTROL_GARBAGE,
    BusinessLogicScanner,
    hpp_winner,
    is_monetary,
    is_numeric,
    is_tamperable,
    looks_like_rejection,
    tamper_values,
    tampering_signal,
)
from orthrus.utils.encoding import with_duplicate_query_param


# ------------------------------------------------------------- numeric helpers
def test_is_numeric_requires_a_digit() -> None:
    assert is_numeric("100") is True
    assert is_numeric("-3.5") is True
    assert is_numeric(" 42 ") is True
    assert is_numeric("inf") is False  # parseable float but no digit -> rejected
    assert is_numeric("abc") is False
    assert is_numeric("") is False


def test_is_tamperable_needs_numeric_value_and_hint() -> None:
    assert is_tamperable("price", "9.99") is True
    assert is_tamperable("quantity", "3") is True
    assert is_tamperable("itemCount", "3") is True
    assert is_tamperable("price", "free") is False  # not numeric
    assert is_tamperable("name", "100") is False  # no value hint


def test_is_monetary_classifies_severity_input() -> None:
    assert is_monetary("unit_price") is True
    assert is_monetary("balance") is True
    assert is_monetary("quantity") is False


def test_tamper_values_are_out_of_band_and_drop_the_original() -> None:
    labels = {label for label, _ in tamper_values("5")}
    assert {"negative", "zero", "fractional", "overflow"} == labels
    # the original value never appears as one of its own tamper variants
    assert all(v != "0" for label, v in tamper_values("0"))
    assert "zero" not in {label for label, _ in tamper_values("0")}


# --------------------------------------------------------------- rejection / signal
def test_looks_like_rejection_on_status_or_keyword() -> None:
    assert looks_like_rejection(400, "ok") is True
    assert looks_like_rejection(200, "Validation failed: must be positive") is True
    assert looks_like_rejection(200, "Order updated. Thank you.") is False


def test_tampering_signal_requires_validating_endpoint() -> None:
    # garbage rejected (field validates) + negative accepted -> signal
    assert tampering_signal(200, 400, "bad", 200, "saved") is True
    # endpoint accepts garbage too -> validates nothing -> inconclusive
    assert tampering_signal(200, 200, "saved", 200, "saved") is False
    # tampered value itself rejected -> no missing validation
    assert tampering_signal(200, 400, "bad", 200, "must be positive") is False
    # baseline (legit value) did not succeed -> can't reason about it
    assert tampering_signal(500, 400, "bad", 200, "saved") is False


# ---------------------------------------------------------------------- HPP logic
def test_hpp_winner_first_when_only_first_survives() -> None:
    assert hpp_winner("A", "B", "echo A", "echo B", "echo A") == "first"


def test_hpp_winner_last_when_only_second_survives() -> None:
    assert hpp_winner("A", "B", "echo A", "echo B", "echo B") == "last"


def test_hpp_winner_none_when_both_or_neither_survive() -> None:
    assert hpp_winner("A", "B", "echo A", "echo B", "echo A and B") is None
    assert hpp_winner("A", "B", "echo A", "echo B", "nothing") is None


def test_hpp_winner_none_when_param_not_reflected() -> None:
    # No reflection in the solo responses -> precedence is unobservable.
    assert hpp_winner("A", "B", "static page", "static page", "static page") is None


def test_with_duplicate_query_param_emits_key_twice_in_order() -> None:
    url = with_duplicate_query_param("http://h/s?other=1", "q", "AA", "BB")
    pairs = parse_qsl(urlsplit(url).query)
    assert ("q", "AA") in pairs and ("q", "BB") in pairs
    assert pairs.index(("q", "AA")) < pairs.index(("q", "BB"))  # first then second
    assert ("other", "1") in pairs  # unrelated params preserved


# ------------------------------------------------------------ scanner integration
class FakeResp:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text


def _ctx(endpoints: list[Endpoint], http: object) -> SimpleNamespace:
    return SimpleNamespace(endpoints=endpoints, http=http)


class TamperHttp:
    """Validates type (rejects garbage) but not range/sign (accepts negatives)."""

    async def request(self, method: str, url: str, **kwargs: object) -> FakeResp:
        qs = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
        if qs.get("price") == CONTROL_GARBAGE:
            return FakeResp(400, "Invalid input: not a number")
        return FakeResp(200, "Order updated. Thank you.")


class PermissiveHttp:
    """Accepts everything (validates nothing) -> tampering is inconclusive."""

    async def request(self, method: str, url: str, **kwargs: object) -> FakeResp:
        return FakeResp(200, "Order updated. Thank you.")


async def test_scanner_flags_tampering_when_field_validates_but_accepts_negative() -> None:
    ep = Endpoint(
        url="http://h/cart?price=100",
        method=HttpMethod.GET,
        params=[Param(name="price", location=ParamLocation.QUERY, value="100")],
    )
    findings = [f async for f in BusinessLogicScanner().scan(_ctx([ep], TamperHttp()))]
    tamper = [f for f in findings if f.vuln_type == "parameter-tampering"]
    assert len(tamper) == 1
    assert tamper[0].severity == Severity.MEDIUM  # 'price' is monetary
    assert tamper[0].parameter == "price"
    assert tamper[0].cwe == "CWE-472"


async def test_scanner_no_tampering_when_endpoint_accepts_garbage() -> None:
    ep = Endpoint(
        url="http://h/cart?price=100",
        method=HttpMethod.GET,
        params=[Param(name="price", location=ParamLocation.QUERY, value="100")],
    )
    findings = [f async for f in BusinessLogicScanner().scan(_ctx([ep], PermissiveHttp()))]
    assert [f for f in findings if f.vuln_type == "parameter-tampering"] == []


class FirstWinsHpp:
    """Reflects the query value; resolves duplicate keys to the FIRST occurrence."""

    async def request(self, method: str, url: str, **kwargs: object) -> FakeResp:
        values = [v for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True) if k == "q"]
        chosen = values[0] if values else ""
        return FakeResp(200, f"search results for {chosen}")


class BothKeptHpp:
    """Reflects BOTH duplicate values -> no clean drop -> no finding."""

    async def request(self, method: str, url: str, **kwargs: object) -> FakeResp:
        values = [v for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True) if k == "q"]
        return FakeResp(200, "search results for " + " ".join(values))


async def test_scanner_flags_hpp_when_duplicate_silently_dropped() -> None:
    ep = Endpoint(
        url="http://h/search?q=x",
        method=HttpMethod.GET,
        params=[Param(name="q", location=ParamLocation.QUERY, value="x")],
    )
    findings = [f async for f in BusinessLogicScanner().scan(_ctx([ep], FirstWinsHpp()))]
    hpp = [f for f in findings if f.vuln_type == "parameter-pollution"]
    assert len(hpp) == 1
    assert hpp[0].cwe == "CWE-235"
    assert hpp[0].parameter == "q"


async def test_scanner_no_hpp_when_both_duplicates_survive() -> None:
    ep = Endpoint(
        url="http://h/search?q=x",
        method=HttpMethod.GET,
        params=[Param(name="q", location=ParamLocation.QUERY, value="x")],
    )
    findings = [f async for f in BusinessLogicScanner().scan(_ctx([ep], BothKeptHpp()))]
    assert [f for f in findings if f.vuln_type == "parameter-pollution"] == []
