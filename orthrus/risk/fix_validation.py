"""Fix-validation gate ladder (Glasswing S11) - the deterministic gates only.

VVAH runs a candidate patch through a gate ladder (syntax, build, rescan, tests,
adversarial "defeat the fix", regression) in an ephemeral worktree, and only
surfaces patches that clear every gate. ORTHRUS generates remediation patches but
did not validate them. This adds the ladder - honestly bounded to the gates a DAST
can run *deterministically*, and explicit that the rest need the target's own
toolchain:

* **applies** - the patch is a real, non-empty change.
* **syntax** - the patched unit parses (Python via ``ast``; other languages are
  skipped, not guessed).
* **scope** - the change stays within a minimal-fix budget (a huge diff is a smell).
* **rescan** - the detector that found the issue no longer fires on the patched
  unit (positive proof the fix removes the finding).
* **regression** - the patch introduces no new detector hits.

Build, full test-suite, and adversarial-LLM gates are **out of scope for a scanner**
and are flagged, not faked (same discipline as MTTA's production-fix leg). Verdicts:
``validated`` (a gate positively re-proved the fix), ``rejected`` (a gate failed),
``inconclusive`` (nothing failed, but the fix could not be positively re-proved).

Pure and deterministic: gates operate on provided content + an injected detector.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from dataclasses import dataclass

VALIDATED, REJECTED, INCONCLUSIVE = "validated", "rejected", "inconclusive"
PASS, FAIL, SKIP = "pass", "fail", "skip"
_PY_LANGS = frozenset({"python", "py", "python3"})
DEFAULT_MAX_LINES = 80


@dataclass(frozen=True)
class GateResult:
    gate: str
    status: str          # pass | fail | skip
    detail: str = ""


@dataclass(frozen=True)
class ValidationResult:
    verdict: str         # validated | rejected | inconclusive
    gates: list[GateResult]
    failed_gate: str | None = None

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "failed_gate": self.failed_gate,
            "gates": [{"gate": g.gate, "status": g.status, "detail": g.detail} for g in self.gates],
        }


def gate_applies(original: str, patched: str) -> GateResult:
    if not (patched or "").strip():
        return GateResult("applies", FAIL, "patched content is empty")
    if patched == original:
        return GateResult("applies", FAIL, "patch is a no-op (identical to the original)")
    return GateResult("applies", PASS, "patch is a real, non-empty change")


def gate_syntax(patched: str, language: str) -> GateResult:
    lang = (language or "").lower()
    if lang in _PY_LANGS:
        try:
            ast.parse(patched)
        except SyntaxError as exc:
            return GateResult("syntax", FAIL, f"Python syntax error: {exc.msg} (line {exc.lineno})")
        return GateResult("syntax", PASS, "patched Python parses")
    return GateResult("syntax", SKIP, f"no deterministic syntax check for '{language or 'unknown'}'")


def gate_scope(lines_changed: int | None, max_lines: int = DEFAULT_MAX_LINES) -> GateResult:
    if lines_changed is None:
        return GateResult("scope", SKIP, "no diff stats supplied")
    if lines_changed > max_lines:
        return GateResult("scope", FAIL,
                          f"{lines_changed} lines changed exceeds the minimal-fix budget of {max_lines}")
    return GateResult("scope", PASS, f"{lines_changed} lines changed (<= {max_lines})")


def gate_rescan(
    detector: Callable[[str], bool] | None, original: str, patched: str
) -> GateResult:
    if detector is None:
        return GateResult("rescan", SKIP, "no detector supplied to re-scan the patched unit")
    if not bool(detector(original)):
        return GateResult("rescan", SKIP, "detector did not fire on the original - nothing to re-prove")
    if bool(detector(patched)):
        return GateResult("rescan", FAIL, "the detector still fires on the patched unit - not fixed")
    return GateResult("rescan", PASS, "the detector no longer fires on the patched unit")


def gate_no_regression(
    regression_detectors: dict[str, Callable[[str], bool]] | None, patched: str
) -> GateResult:
    if not regression_detectors:
        return GateResult("regression", SKIP, "no regression detectors supplied")
    fired = sorted(name for name, det in regression_detectors.items() if det(patched))
    if fired:
        return GateResult("regression", FAIL, f"patch introduced new issue(s): {', '.join(fired)}")
    return GateResult("regression", PASS, "no new issues introduced by the patch")


def run_ladder(
    *,
    original: str,
    patched: str,
    language: str = "",
    lines_changed: int | None = None,
    detector: Callable[[str], bool] | None = None,
    regression_detectors: dict[str, Callable[[str], bool]] | None = None,
    max_lines: int = DEFAULT_MAX_LINES,
) -> ValidationResult:
    """Run the deterministic gate ladder over a candidate patch."""
    gates = [
        gate_applies(original, patched),
        gate_syntax(patched, language),
        gate_scope(lines_changed, max_lines),
        gate_rescan(detector, original, patched),
        gate_no_regression(regression_detectors, patched),
    ]
    failed = next((g for g in gates if g.status == FAIL), None)
    if failed is not None:
        verdict = REJECTED
    elif any(g.gate == "rescan" and g.status == PASS for g in gates):
        verdict = VALIDATED     # a gate positively re-proved the fix
    else:
        verdict = INCONCLUSIVE  # nothing failed, but the fix was not positively re-proven
    return ValidationResult(verdict=verdict, gates=gates,
                            failed_gate=failed.gate if failed else None)


__all__ = [
    "VALIDATED", "REJECTED", "INCONCLUSIVE", "PASS", "FAIL", "SKIP",
    "GateResult", "ValidationResult", "run_ladder",
    "gate_applies", "gate_syntax", "gate_scope", "gate_rescan", "gate_no_regression",
]
