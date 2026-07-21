"""gRPC reflection scanner: service filtering + (live) reflection detection."""

from __future__ import annotations

from types import SimpleNamespace

import orthrus.scanners.grpc_probe as grpc_probe
from orthrus.scanners.grpc_probe import GrpcReflectionScanner, user_services


def test_user_services_drops_internal():
    names = [
        "myapp.v1.Greeter",
        "billing.Payments",
        "grpc.reflection.v1alpha.ServerReflection",
        "grpc.health.v1.Health",
    ]
    assert user_services(names) == ["myapp.v1.Greeter", "billing.Payments"]


def test_user_services_empty():
    assert user_services(["grpc.reflection.v1alpha.ServerReflection"]) == []


async def test_scan_noop_when_reflection_unavailable(monkeypatch):
    # Satisfy the grpcio-availability guard so we test the "no service answered"
    # path itself (not the "grpc not installed" early-return). Keeps the test
    # hermetic - it runs identically with or without the optional grpc extra.
    monkeypatch.setattr(grpc_probe, "grpc", object())

    async def none_list(self, host, port, tls):  # noqa: ANN001
        return None

    monkeypatch.setattr(GrpcReflectionScanner, "_list_services", none_list)
    ctx = SimpleNamespace(
        endpoints=[],
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(target="http://h:50051/"),
    )
    assert [f async for f in GrpcReflectionScanner().scan(ctx)] == []


async def test_scan_flags_when_services_returned(monkeypatch):
    # Satisfy the grpcio guard so the scan logic runs even where the optional
    # grpc extra isn't installed (e.g. base CI) - the real reflection call is
    # replaced by `fake_list`, so grpcio itself is never needed.
    monkeypatch.setattr(grpc_probe, "grpc", object())

    async def fake_list(self, host, port, tls):  # noqa: ANN001
        return ["orthrus.test.Greeter", "grpc.reflection.v1alpha.ServerReflection"]

    monkeypatch.setattr(GrpcReflectionScanner, "_list_services", fake_list)
    ctx = SimpleNamespace(
        endpoints=[],
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(target="http://h:50051/"),
    )
    findings = [f async for f in GrpcReflectionScanner().scan(ctx)]
    assert len(findings) == 1
    assert findings[0].vuln_type == "grpc-reflection"
    assert findings[0].cwe == "CWE-200"
    assert "orthrus.test.Greeter" in findings[0].evidence.notes
