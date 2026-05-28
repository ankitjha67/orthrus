"""URL / encoding helpers used by scanners (PRD utils/encoding)."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def with_query_param(url: str, name: str, value: str) -> str:
    """Return ``url`` with query parameter ``name`` set to ``value``.

    Replaces an existing occurrence; appends if absent. Other params are kept.
    """
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    new_pairs: list[tuple[str, str]] = []
    for key, val in pairs:
        if key == name:
            new_pairs.append((key, value))
            replaced = True
        else:
            new_pairs.append((key, val))
    if not replaced:
        new_pairs.append((name, value))
    query = urlencode(new_pairs, doseq=True)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query, ""))


__all__ = ["with_query_param"]
