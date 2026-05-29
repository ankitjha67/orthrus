"""Tests for the mass-assignment scanner's pure detection logic."""

from __future__ import annotations

from orthrus.core.schemas import Endpoint, HttpMethod, Param, ParamLocation, Severity
from orthrus.scanners.mass_assignment import (
    PRIVILEGED_FIELDS,
    _base_body,
    _body_location,
    _severity,
    detect_bound_fields,
)


def test_detect_bound_fields_flags_reflected_nonces():
    probes = {"role": "orthrusAB0", "is_admin": "orthrusAB1", "balance": "orthrusAB2"}
    baseline = '{"id":"1","name":"guest","role":"user"}'
    injected = '{"id":"1","name":"guest","role":"orthrusAB0","is_admin":"orthrusAB1"}'
    bound = detect_bound_fields(probes, baseline, injected)
    assert set(bound) == {"role", "is_admin"}  # balance nonce not reflected


def test_detect_bound_fields_ignores_nonces_present_in_baseline():
    # A nonce already in the baseline is not evidence of binding.
    probes = {"role": "orthrusXX0"}
    baseline = "noise orthrusXX0 noise"
    injected = "noise orthrusXX0 noise"
    assert detect_bound_fields(probes, baseline, injected) == []


def test_detect_bound_fields_empty_when_nothing_reflected():
    probes = {"role": "orthrusZZ0", "admin": "orthrusZZ1"}
    assert detect_bound_fields(probes, "baseline", "no privileged fields echoed") == []


def test_severity_high_for_authz_fields():
    assert _severity(["role"]) == Severity.HIGH
    assert _severity(["is_admin"]) == Severity.HIGH
    assert _severity(["permissions", "balance"]) == Severity.HIGH  # any high-risk -> HIGH


def test_severity_medium_for_non_authz_fields():
    assert _severity(["balance"]) == Severity.MEDIUM
    assert _severity(["verified", "enabled"]) == Severity.MEDIUM


def test_body_location_prefers_json_then_body():
    json_ep = Endpoint(
        url="https://x.test/a",
        method=HttpMethod.POST,
        params=[Param(name="a", location=ParamLocation.JSON)],
    )
    body_ep = Endpoint(
        url="https://x.test/b",
        method=HttpMethod.POST,
        params=[Param(name="a", location=ParamLocation.BODY)],
    )
    query_ep = Endpoint(
        url="https://x.test/c",
        method=HttpMethod.POST,
        params=[Param(name="a", location=ParamLocation.QUERY)],
    )
    assert _body_location(json_ep) == ParamLocation.JSON
    assert _body_location(body_ep) == ParamLocation.BODY
    assert _body_location(query_ep) is None  # nothing to bind a body onto


def test_base_body_uses_param_sample_values():
    ep = Endpoint(
        url="https://x.test/a",
        method=HttpMethod.POST,
        params=[
            Param(name="name", location=ParamLocation.BODY, value="guest"),
            Param(name="x", location=ParamLocation.BODY),  # no value -> placeholder
            Param(name="q", location=ParamLocation.QUERY, value="ignored"),
        ],
    )
    assert _base_body(ep, ParamLocation.BODY) == {"name": "guest", "x": "1"}


def test_privileged_field_list_covers_core_escalation_names():
    names = {f.lower() for f in PRIVILEGED_FIELDS}
    for expected in ("role", "is_admin", "isadmin", "verified", "permissions"):
        assert expected in names
