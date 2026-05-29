"""WAF / filter-evasion payload encoders (PRD §6 payload mutation).

A pure, deterministic library of payload transforms that active scanners use to
slip a probe past naive signature- or keyword-matching web application
firewalls. Confirming a vulnerability that a WAF would otherwise mask is the
point; these transforms are not themselves exploits, and every request still
flows through the scope-enforced HttpClient.

Two layers of transforms exist because the HTTP transport already percent-encodes
query and form values:

* **Encoding** transforms (``url_encode``, ``double_url_encode``, ``html_entity``,
  ``unicode_escape``) change the *bytes on the wire*. They help only where the
  caller controls those bytes directly (raw request bodies, header values); for
  ordinary query/form params the transport re-encodes them and the server
  decodes back to the original, so they round-trip to a no-op.
* **Decoded-form** transforms (``mixed_case``, ``comment_spacing``) change what
  the server sees *after* decoding, so they survive transport and defeat
  signature rules. ``transport_safe_variants`` returns only these.

All transforms are deterministic so a detection produced with an evasion variant
is reproducible.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import quote

# Characters most WAF signatures key on. Encoding just these is stealthier than
# encoding the whole payload and is usually enough to break a signature match.
SPECIAL_CHARS = "<>\"'=()/\\;:&%* \t\n"

_WS = re.compile(r"\s+")


def url_encode(payload: str) -> str:
    """Percent-encode every character, including normally-safe ones."""
    return quote(payload, safe="")


def url_encode_special(payload: str) -> str:
    """Percent-encode only the filter-significant characters, leaving the rest."""
    return "".join(f"%{ord(c):02X}" if c in SPECIAL_CHARS else c for c in payload)


def double_url_encode(payload: str) -> str:
    """Percent-encode twice (``<`` -> ``%253C``).

    Defeats filters that URL-decode once before matching but hand the still-
    encoded bytes to a backend that decodes a second time.
    """
    return url_encode(url_encode(payload))


def html_entity(payload: str) -> str:
    """Encode filter-significant characters as decimal HTML entities (``&#60;``)."""
    return "".join(f"&#{ord(c)};" if c in SPECIAL_CHARS else c for c in payload)


def unicode_escape(payload: str) -> str:
    r"""Encode filter-significant characters as ``\uXXXX`` escapes (JS / JSON sinks)."""
    return "".join(f"\\u{ord(c):04x}" if c in SPECIAL_CHARS else c for c in payload)


def mixed_case(payload: str) -> str:
    """Alternate letter case, defeating case-sensitive keyword rules.

    Deterministic (alternates on each letter) so detections reproduce. Non-letter
    characters are left untouched; a payload with no letters is unchanged.
    """
    out: list[str] = []
    flip = False
    for ch in payload:
        if ch.isalpha():
            out.append(ch.upper() if flip else ch.lower())
            flip = not flip
        else:
            out.append(ch)
    return "".join(out)


def comment_spacing(payload: str) -> str:
    """Replace each run of whitespace with an inline SQL comment ``/**/``.

    Survives transport (no whitespace to be re-encoded) and breaks rules that key
    on ``UNION SELECT``-style space-delimited keyword sequences.
    """
    return _WS.sub("/**/", payload)


# Ordered so the cheapest, most broadly useful transforms come first. Each is
# applied to the *original* payload (transforms are not chained), so every
# variant is an independent encoding of the same logical payload.
_ENCODERS: tuple[tuple[str, Callable[[str], str]], ...] = (
    ("mixed-case", mixed_case),
    ("comment-spacing", comment_spacing),
    ("url-encode", url_encode_special),
    ("double-url-encode", double_url_encode),
    ("html-entity", html_entity),
    ("unicode-escape", unicode_escape),
)

# Transforms whose effect survives query/form transport encoding (see module doc).
_TRANSPORT_SAFE = frozenset({"mixed-case", "comment-spacing"})


def variants(
    payload: str, *, max_variants: int = 6, transport_safe: bool = False
) -> list[tuple[str, str]]:
    """Return up to ``max_variants`` ``(label, encoded)`` pairs, raw form first.

    De-duplicates: a transform that leaves the payload unchanged (e.g. comment
    spacing on a payload with no whitespace, or mixed case on punctuation) is
    skipped, so a caller never spends a request on an encoding identical to one
    already tried. With ``transport_safe=True`` only the decoded-form transforms
    that survive query/form encoding are considered.
    """
    out: list[tuple[str, str]] = [("raw", payload)]
    seen = {payload}
    for label, fn in _ENCODERS:
        if len(out) >= max_variants:
            break
        if transport_safe and label not in _TRANSPORT_SAFE:
            continue
        try:
            encoded = fn(payload)
        except Exception:  # noqa: BLE001  (a bad transform must never abort scanning)
            continue
        if not encoded or encoded in seen:
            continue
        seen.add(encoded)
        out.append((label, encoded))
    return out


def transport_safe_variants(payload: str, *, max_variants: int = 3) -> list[tuple[str, str]]:
    """``variants`` restricted to transforms that survive query/form transport."""
    return variants(payload, max_variants=max_variants, transport_safe=True)


__all__ = [
    "SPECIAL_CHARS",
    "url_encode",
    "url_encode_special",
    "double_url_encode",
    "html_entity",
    "unicode_escape",
    "mixed_case",
    "comment_spacing",
    "variants",
    "transport_safe_variants",
]
