"""Pure matcher/extractor evaluation for declarative templates.

Operates on a small :class:`MatchInput` snapshot of a response (status, body,
joined headers) so it can be unit-tested without any HTTP layer. No network, no
regex compilation caching surprises — deterministic given its inputs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from hydra.templates.schema import Extractor, Matcher, RequestTemplate


@dataclass
class MatchInput:
    """The slice of an HTTP response that matchers see."""

    status: int
    body: str
    headers: str  # headers rendered as "Key: value\n" lines

    def part(self, name: str) -> str:
        if name == "status":
            return str(self.status)
        if name == "header":
            return self.headers
        if name in ("all", "raw"):
            return f"{self.status}\n{self.headers}\n{self.body}"
        return self.body  # default: body


def _combine(results: list[bool], condition: str) -> bool:
    if not results:
        return False
    return all(results) if condition.lower() == "and" else any(results)


def eval_matcher(matcher: Matcher, data: MatchInput) -> tuple[bool, list[str]]:
    """Return ``(matched, matched_strings)`` for a single matcher.

    ``negative`` flips the boolean (but never the matched-strings list).
    """
    matched_strings: list[str] = []
    mtype = matcher.type.lower()

    if mtype == "status":
        result = data.status in matcher.status
    elif mtype == "size":
        result = len(data.body) in matcher.size
    elif mtype == "word":
        hay = data.part(matcher.part)
        if matcher.case_insensitive:
            hay_cmp = hay.lower()
            checks = [(w, w.lower() in hay_cmp) for w in matcher.words]
        else:
            checks = [(w, w in hay) for w in matcher.words]
        matched_strings = [w for w, ok in checks if ok]
        result = _combine([ok for _, ok in checks], matcher.condition)
    elif mtype == "regex":
        hay = data.part(matcher.part)
        flags = re.IGNORECASE if matcher.case_insensitive else 0
        per_pattern: list[bool] = []
        for pattern in matcher.regex:
            try:
                found = re.findall(pattern, hay, flags)
            except re.error:
                per_pattern.append(False)
                continue
            per_pattern.append(bool(found))
            for hit in found:
                matched_strings.append(hit if isinstance(hit, str) else str(hit))
        result = _combine(per_pattern, matcher.condition)
    else:
        return False, []  # unknown matcher type never matches

    if matcher.negative:
        return (not result), matched_strings
    return result, matched_strings


def eval_request_matchers(
    request: RequestTemplate, data: MatchInput
) -> tuple[bool, list[str]]:
    """Evaluate all matchers of a request under its ``matchers-condition``."""
    if not request.matchers:
        return False, []
    outcomes: list[bool] = []
    all_matched: list[str] = []
    for matcher in request.matchers:
        ok, strings = eval_matcher(matcher, data)
        outcomes.append(ok)
        if ok:
            all_matched.extend(strings)
    return _combine(outcomes, request.matchers_condition), all_matched


def run_extractors(extractors: list[Extractor], data: MatchInput) -> dict[str, str]:
    """Pull named values out of a response (best-effort, first hit per extractor)."""
    out: dict[str, str] = {}
    for idx, extractor in enumerate(extractors):
        key = extractor.name or f"extract{idx}"
        if extractor.type.lower() == "regex":
            hay = data.part(extractor.part)
            for pattern in extractor.regex:
                try:
                    m = re.search(pattern, hay)
                except re.error:
                    continue
                if m:
                    out[key] = m.group(extractor.group) if m.groups() or extractor.group == 0 else m.group(0)
                    break
        elif extractor.type.lower() == "kval":
            for wanted in extractor.kval:
                for line in data.headers.splitlines():
                    name, _, value = line.partition(":")
                    if name.strip().lower() == wanted.lower():
                        out[wanted] = value.strip()
                        break
    return out


__all__ = ["MatchInput", "eval_matcher", "eval_request_matchers", "run_extractors"]
