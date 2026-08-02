"""Detector-level precision/recall corpus (real numbers, no server needed).

Runs ORTHRUS's *pure verdict functions* - the deterministic core of each passive
scanner - against a labelled corpus of **vulnerable** and **known-clean** inputs,
and tallies a confusion matrix per detector. Because these functions take plain
inputs (headers, a TLS-facts dict, an HTML string, a cookie line) and return
findings with no network or browser, the measurement is fully reproducible in a
unit test and produces genuine precision/recall - including the false-positive
rate on clean input that a detection-only benchmark never measures.

Scope (honest): this covers the pure-verdict passive detectors. Active scanners
(SQLi/XSS/SSRF differentials) and the confirmation phase are measured end-to-end
by the live harness (`orthrus.benchmark.runner`); see docs/METHODOLOGY.md.
"""

from __future__ import annotations

import json
from pathlib import Path

from orthrus.benchmark.metrics import ConfusionMatrix, aggregate

DATA_DIR = Path(__file__).parent / "data"
CORPUS_FILE = DATA_DIR / "detector_corpus.json"


def _fire_headers(inp: dict) -> bool:
    from orthrus.scanners.headers import analyze_headers

    return len(analyze_headers(inp["url"], inp["headers"])) > 0


def _fire_tls(inp: dict) -> bool:
    from orthrus.scanners.tls_analyzer import classify_tls

    return len(classify_tls(inp["facts"])) > 0


def _fire_sri(inp: dict) -> bool:
    from orthrus.scanners.sri import find_missing_sri

    return len(find_missing_sri(inp["html"], inp["page_url"])) > 0


def _fire_session_url(inp: dict) -> bool:
    from orthrus.scanners.session_fixation import session_token_in_url

    return session_token_in_url(inp["url"]) is not None


def _fire_cookie(inp: dict) -> bool:
    from orthrus.scanners.auth import cookie_issues

    return len(cookie_issues(inp["set_cookie"], bool(inp.get("is_https", True)))) > 0


def _fire_email_auth(inp: dict) -> bool:
    # "Fired" = a spoofable-domain finding (MEDIUM+), not the LOW hardening notes.
    from orthrus.core.schemas import Severity
    from orthrus.scanners.email_auth import classify_email_auth

    issues = classify_email_auth(inp["records"])
    return any(sev in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL) for sev, *_ in issues)


def _fire_mixed_content(inp: dict) -> bool:
    from orthrus.scanners.mixed_content import find_mixed_content

    return len(find_mixed_content(inp["html"], inp["page_url"])) > 0


DISPATCH = {
    "headers": _fire_headers,
    "tls": _fire_tls,
    "sri": _fire_sri,
    "session-url": _fire_session_url,
    "cookie": _fire_cookie,
    "email-auth": _fire_email_auth,
    "mixed-content": _fire_mixed_content,
}


def load_corpus(path: str | Path | None = None) -> list[dict]:
    src = Path(path) if path else CORPUS_FILE
    cases = json.loads(src.read_text(encoding="utf-8"))
    if not isinstance(cases, list) or not cases:
        raise ValueError(f"detector corpus '{src}' must be a non-empty JSON list")
    return cases


def run_detector_corpus(
    cases: list[dict] | None = None,
) -> tuple[dict[str, ConfusionMatrix], ConfusionMatrix, list[str]]:
    """Run every case through its detector; return (per-detector, overall, errors)."""
    cases = cases if cases is not None else load_corpus()
    per: dict[str, ConfusionMatrix] = {}
    errors: list[str] = []
    for i, case in enumerate(cases):
        name = case.get("detector", "")
        adapter = DISPATCH.get(name)
        if adapter is None:
            errors.append(f"case {i}: unknown detector {name!r}")
            continue
        try:
            fired = adapter(case["input"])
        except Exception as exc:  # a detector raising on a corpus input is itself a failure
            errors.append(f"case {i} ({name}): {type(exc).__name__}: {exc}")
            continue
        cm = ConfusionMatrix.from_case(bool(case.get("should_fire", False)), fired)
        per[name] = per.get(name, ConfusionMatrix()) + cm
    return per, aggregate(list(per.values())), errors


__all__ = ["DISPATCH", "load_corpus", "run_detector_corpus", "CORPUS_FILE"]
