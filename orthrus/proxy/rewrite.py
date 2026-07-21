"""Match & Replace - rule-based request/response rewriting for the proxy.

Burp/Caido "Match and Replace": rewrite parts of traffic as it passes through the
proxy. Add an identifying/auth header to every request, strip a response security
header to test client-side controls, flip a role field in a JSON body, and so on.

Rules are JSON (``orthrus proxy --rewrite rules.json``):

    [
      {"part": "req-header",  "match": "+",  "replace": "X-Bug-Bounty: myhandle"},
      {"part": "resp-header", "match": "(?i)^content-security-policy:.*", "replace": ""},
      {"part": "req-body",    "match": "\\"role\\":\\"user\\"", "replace": "\\"role\\":\\"admin\\""}
    ]

``part`` is req-header / req-body / resp-header / resp-body. For header parts a
``match`` of ``"+"`` (or empty) *adds* the ``replace`` line; a rule whose replace
empties a header line *drops* it; otherwise the regex is applied. The rules only
ever run for in-scope traffic the proxy already allowed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

PARTS = ("req-header", "req-body", "resp-header", "resp-body")
_ADD = ("", "+")


@dataclass
class RewriteRule:
    part: str
    match: str
    replace: str
    enabled: bool = True


def load_rules(text: str) -> list[RewriteRule]:
    """Parse a JSON rules document into enabled RewriteRules (ignores unknown parts)."""
    data = json.loads(text) if (text or "").strip() else []
    rules: list[RewriteRule] = []
    for d in data if isinstance(data, list) else []:
        if not isinstance(d, dict) or d.get("part") not in PARTS:
            continue
        if d.get("enabled", True):
            rules.append(RewriteRule(d["part"], str(d.get("match", "")),
                                     str(d.get("replace", "")), True))
    return rules


class RewriteEngine:
    """Applies a set of Match & Replace rules to request/response headers + bodies."""

    def __init__(self, rules: list[RewriteRule]) -> None:
        self.rules = [r for r in rules if r.enabled]

    def _headers(self, headers: list[tuple[str, str]], part: str) -> list[tuple[str, str]]:
        subs = [r for r in self.rules if r.part == part and r.match not in _ADD]
        adds = [r.replace for r in self.rules if r.part == part and r.match in _ADD]
        out: list[tuple[str, str]] = []
        for name, value in headers:
            line = f"{name}: {value}"
            for r in subs:
                line = re.sub(r.match, r.replace, line)
            if line.strip():                       # an emptied line is dropped
                n, _, v = line.partition(":")
                out.append((n.strip(), v.strip()))
        for add in adds:
            n, _, v = add.partition(":")
            if n.strip():
                out.append((n.strip(), v.strip()))
        return out

    def _body(self, body: bytes, part: str) -> bytes:
        subs = [r for r in self.rules if r.part == part and r.match not in _ADD]
        if not body or not subs:
            return body
        text = body.decode("utf-8", "surrogateescape")
        for r in subs:
            text = re.sub(r.match, r.replace, text)
        return text.encode("utf-8", "surrogateescape")

    # convenience wrappers used by the proxy
    def request_headers(self, headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
        return self._headers(headers, "req-header")

    def request_body(self, body: bytes) -> bytes:
        return self._body(body, "req-body")

    def response_headers(self, headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
        return self._headers(headers, "resp-header")

    def response_body(self, body: bytes) -> bytes:
        return self._body(body, "resp-body")

    def request_headers_dict(self, headers: dict[str, str]) -> dict[str, str]:
        """Header-dict variant (proxy forwards as a dict) - preserves last-wins order."""
        return dict(self.request_headers(list(headers.items())))


__all__ = ["RewriteRule", "RewriteEngine", "load_rules", "PARTS"]
