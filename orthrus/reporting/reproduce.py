"""Per-finding reproduction snippets - curl, Python, and a raw request for Burp.

Pentesters live in curl, ``requests``/``httpx``, and Burp Repeater. For every
finding that captured a request, ORTHRUS emits copy-paste blocks so the reader
can re-run the exact request that produced the evidence, instead of hand-rebuilding
it from a prose description. The snippets are derived from the recorded
``request_raw`` (parsed by :func:`orthrus.proxy.replay.parse_raw_http`) plus the
finding URL, so they reflect what the scanner actually sent.

Headers that a client sets for itself (``Host``, ``Content-Length``) are dropped
so the snippet doesn't fight the tool; credential headers (``Cookie``,
``Authorization``) are kept because reproduction needs them - the report is
already marked CONFIDENTIAL and carries the same evidence verbatim.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from orthrus.proxy.replay import RequestSpec, parse_raw_http

# Client-managed headers: emitting them would duplicate/conflict with what curl,
# httpx, or the browser computes from the URL and body.
_DROP_HEADERS = {"host", "content-length", "connection", "accept-encoding"}

# A genuine HTTP request line: "METHOD target HTTP/x.y". Some scanners stash a
# payload description or a GraphQL query dict in request_raw instead of a raw
# request; those must NOT be mistaken for HTTP (or curl gets a garbage method).
_REQUEST_LINE = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT) \S+ HTTP/\d(\.\d)?\s*$"
)


def _sh_squote(value: str) -> str:
    """POSIX single-quote a shell argument (``'`` -> ``'\\''``)."""
    return "'" + value.replace("'", "'\\''") + "'"


def _clean_headers(spec: RequestSpec) -> list[tuple[str, str]]:
    return [(k, v) for k, v in spec.headers.items() if k.lower() not in _DROP_HEADERS]


def _spec_from(url: str, request_raw: str | None) -> RequestSpec | None:
    """Build a RequestSpec from recorded evidence, or a bare GET from the URL."""
    parsed = urlsplit(url) if url else None
    scheme = (parsed.scheme if parsed else "") or "https"
    raw = (request_raw or "").replace("\r\n", "\n").lstrip("\n")
    first_line = raw.split("\n", 1)[0].strip() if raw else ""
    if _REQUEST_LINE.match(first_line):
        # An origin-form request line (path only) needs a Host header to become an
        # absolute URL; borrow it from the finding URL when the capture lacks one.
        has_host = any(line.lower().startswith("host:") for line in raw.split("\n"))
        if not has_host and parsed and parsed.netloc:
            lines = raw.split("\n")
            lines.insert(1, f"Host: {parsed.netloc}")
            raw = "\n".join(lines)
        try:
            spec = parse_raw_http(raw, default_scheme=scheme)
        except ValueError:
            spec = None
        if spec is not None:
            # Prefer the finding's absolute URL if the parser still couldn't resolve a host.
            if url and not urlsplit(spec.url).netloc:
                spec = spec.tweaked(url=url)
            return spec
    # request_raw was absent or not a real HTTP request: a bare GET to the URL still
    # reproduces observational findings (missing header, cookie flag, exposed file).
    if url:
        return RequestSpec(method="GET", url=url, headers={}, body="")
    return None


def _curl(spec: RequestSpec) -> str:
    parts = ["curl -sk"]
    if spec.method.upper() != "GET":
        parts.append(f"-X {spec.method.upper()}")
    parts.append(_sh_squote(spec.url))
    lines = [" ".join(parts)]
    for k, v in _clean_headers(spec):
        lines.append(f"  -H {_sh_squote(f'{k}: {v}')}")
    if spec.body:
        lines.append(f"  --data {_sh_squote(spec.body)}")
    return " \\\n".join(lines)


def _python(spec: RequestSpec) -> str:
    headers = dict(_clean_headers(spec))
    out = [
        "import httpx  # or: import requests as httpx",
        "",
        "resp = httpx.request(",
        f"    {spec.method.upper()!r},",
        f"    {spec.url!r},",
    ]
    if headers:
        out.append(f"    headers={headers!r},")
    if spec.body:
        out.append(f"    content={spec.body!r},")
    out += ["    verify=False,  # test targets often use self-signed TLS", ")",
            "print(resp.status_code)", "print(resp.text[:2000])"]
    return "\n".join(out)


def build_snippets(*, url: str | None, request_raw: str | None) -> dict[str, str]:
    """Return ``{"curl", "python", "raw"}`` reproduction snippets, or ``{}``.

    ``raw`` is a well-formed HTTP request suitable for pasting straight into Burp
    Repeater. Returns an empty dict when there is nothing to reproduce (no URL and
    no recorded request).
    """
    spec = _spec_from(url or "", request_raw)
    if spec is None:
        return {}
    return {"curl": _curl(spec), "python": _python(spec), "raw": spec.to_raw()}


__all__ = ["build_snippets"]
