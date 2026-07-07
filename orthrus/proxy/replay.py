"""Request replay — the mini-Repeater.

Resend a previously-recorded request (a finding's captured request, a proxy
capture, or a raw request pasted Burp-style) with optional tweaks — a different
method, URL, header, or body — and observe the response. This bridges an
automated finding into hands-on verification: `orthrus replay` a finding's
recorded request, tweak the payload, and watch what changes.

Scope enforcement is load-bearing here too: every replayed request is validated
against the authorized scope before it leaves, exactly like a scan request, so a
repeater built on this can never wander off the engagement.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from time import perf_counter
from urllib.parse import urlsplit

import httpx

from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeValidator

logger = get_logger("replay")

_ABS_URL = re.compile(r"^https?://", re.IGNORECASE)


@dataclass
class RequestSpec:
    """A replayable request: method, absolute URL, headers, and a text body."""

    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    def tweaked(
        self,
        *,
        method: str | None = None,
        url: str | None = None,
        set_headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> RequestSpec:
        """Return a copy with the given overrides applied (headers merged, not replaced)."""
        headers = dict(self.headers)
        for name, value in (set_headers or {}).items():
            # case-insensitive replace: drop any existing header of the same name first
            headers = {k: v for k, v in headers.items() if k.lower() != name.lower()}
            headers[name] = value
        return RequestSpec(
            method=(method or self.method).upper(),
            url=url or self.url,
            headers=headers,
            body=self.body if body is None else body,
        )

    def to_raw(self) -> str:
        parts = urlsplit(self.url)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        lines = [f"{self.method} {path} HTTP/1.1"]
        if "host" not in {k.lower() for k in self.headers}:
            lines.append(f"Host: {parts.netloc}")
        lines += [f"{k}: {v}" for k, v in self.headers.items()]
        return "\r\n".join(lines) + "\r\n\r\n" + self.body


def parse_raw_http(raw: str, *, default_scheme: str = "https") -> RequestSpec:
    """Parse a raw HTTP request (request line + headers + optional body).

    Accepts both absolute-form (`GET https://h/p HTTP/1.1`) and origin-form
    (`GET /p HTTP/1.1` + a `Host:` header). Origin-form URLs are resolved against
    the Host header using ``default_scheme``.
    """
    text = raw.replace("\r\n", "\n").strip("\n")
    if not text:
        raise ValueError("empty request")
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    bits = lines[0].split()
    if len(bits) < 2:
        raise ValueError(f"malformed request line: {lines[0]!r}")
    method, target = bits[0].upper(), bits[1]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip()] = value.strip()
    if _ABS_URL.match(target):
        url = target
    else:
        host = next((v for k, v in headers.items() if k.lower() == "host"), None)
        if not host:
            raise ValueError("origin-form request needs a Host header to build the URL")
        url = f"{default_scheme}://{host}{target if target.startswith('/') else '/' + target}"
    return RequestSpec(method=method, url=url, headers=headers, body=body)


@dataclass
class ReplayResult:
    method: str
    url: str
    status: int | None = None
    reason: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""
    elapsed_ms: float = 0.0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None


async def replay(
    spec: RequestSpec,
    validator: ScopeValidator,
    *,
    timeout: float = 30.0,  # noqa: ASYNC109 — httpx's own timeout is the right mechanism here
    follow_redirects: bool = False,
    verify_tls: bool = False,
) -> ReplayResult:
    """Send ``spec`` once, scope-checked. Out-of-scope or transport errors return
    a ReplayResult with ``error`` set rather than raising."""
    decision = validator.check(spec.url)
    if not decision.allowed:
        return ReplayResult(spec.method, spec.url, error=f"blocked: out of scope ({decision.reason})")
    content = spec.body.encode("utf-8", "surrogateescape") if spec.body else None
    try:
        async with httpx.AsyncClient(
            verify=verify_tls, timeout=timeout, follow_redirects=follow_redirects
        ) as client:
            start = perf_counter()
            resp = await client.request(
                spec.method, spec.url, headers=spec.headers or None, content=content
            )
            elapsed = (perf_counter() - start) * 1000.0
    except (httpx.HTTPError, httpx.InvalidURL) as exc:
        return ReplayResult(spec.method, spec.url, error=f"{type(exc).__name__}: {exc}")
    return ReplayResult(
        method=spec.method,
        url=str(resp.url),
        status=resp.status_code,
        reason=resp.reason_phrase or "",
        headers=list(resp.headers.items()),
        body=resp.text,
        elapsed_ms=round(elapsed, 1),
    )


__all__ = ["RequestSpec", "ReplayResult", "parse_raw_http", "replay"]
