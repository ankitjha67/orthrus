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


def with_duplicate_query_param(url: str, name: str, first: str, second: str) -> str:
    """Return ``url`` with ``name`` present twice: ``name=first&name=second``.

    Any pre-existing occurrences of ``name`` are dropped first; other params are
    preserved in order. Used by the HTTP-parameter-pollution probe to observe how
    a server resolves duplicate query keys.
    """
    parts = urlsplit(url)
    pairs = [
        (key, val)
        for key, val in parse_qsl(parts.query, keep_blank_values=True)
        if key != name
    ]
    pairs.append((name, first))
    pairs.append((name, second))
    query = urlencode(pairs, doseq=True)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query, ""))


__all__ = ["with_query_param", "with_duplicate_query_param"]
