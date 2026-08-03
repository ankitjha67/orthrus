"""Tests for the deterministic fix-validation gate ladder."""

from __future__ import annotations

from orthrus.risk.fix_validation import (
    INCONCLUSIVE,
    REJECTED,
    VALIDATED,
    gate_applies,
    gate_scope,
    gate_syntax,
    run_ladder,
)


# A toy "detector": fires when the dangerous pattern is present.
def _fires(content: str) -> bool:
    return "eval(" in content

VULN = "x = eval(user_input)\n"
FIXED = "x = int(user_input)\n"


# --- individual gates ----------------------------------------------------------

def test_gate_applies():
    assert gate_applies(VULN, FIXED).status == "pass"
    assert gate_applies(VULN, VULN).status == "fail"       # no-op
    assert gate_applies(VULN, "   ").status == "fail"       # empty


def test_gate_syntax_python():
    assert gate_syntax("def f():\n    return 1\n", "python").status == "pass"
    assert gate_syntax("def f(:\n", "python").status == "fail"
    assert gate_syntax("int x = 1;", "go").status == "skip"  # not deterministically checkable


def test_gate_scope_budget():
    assert gate_scope(10, max_lines=80).status == "pass"
    assert gate_scope(200, max_lines=80).status == "fail"
    assert gate_scope(None).status == "skip"


# --- full ladder verdicts ------------------------------------------------------

def test_validated_when_rescan_positively_proves_the_fix():
    res = run_ladder(original=VULN, patched=FIXED, language="python",
                     lines_changed=1, detector=_fires)
    assert res.verdict == VALIDATED and res.failed_gate is None
    assert any(g.gate == "rescan" and g.status == "pass" for g in res.gates)


def test_rejected_when_detector_still_fires():
    still_vuln = "x = eval(sanitize(user_input))\n"
    res = run_ladder(original=VULN, patched=still_vuln, language="python", detector=_fires)
    assert res.verdict == REJECTED and res.failed_gate == "rescan"


def test_rejected_on_bad_syntax_before_rescan():
    res = run_ladder(original=VULN, patched="x = int(:\n", language="python", detector=_fires)
    assert res.verdict == REJECTED and res.failed_gate == "syntax"


def test_rejected_when_scope_budget_exceeded():
    res = run_ladder(original=VULN, patched=FIXED, language="python",
                     lines_changed=500, detector=_fires)
    assert res.verdict == REJECTED and res.failed_gate == "scope"


def test_inconclusive_without_a_detector():
    # Nothing fails, but nothing positively re-proves the fix either.
    res = run_ladder(original=VULN, patched=FIXED, language="python", lines_changed=1)
    assert res.verdict == INCONCLUSIVE and res.failed_gate is None


def test_regression_gate_rejects_new_issue():
    res = run_ladder(original=VULN, patched="import pickle; eval2=1\n", language="python",
                     detector=_fires, regression_detectors={"pickle-use": lambda c: "pickle" in c})
    # detector no longer fires (fix ok) but a regression detector does -> rejected
    assert res.verdict == REJECTED and res.failed_gate == "regression"


def test_is_deterministic_and_serialisable():
    kw = dict(original=VULN, patched=FIXED, language="python", lines_changed=1, detector=_fires)
    a, b = run_ladder(**kw), run_ladder(**kw)
    assert a.as_dict() == b.as_dict()
    assert a.as_dict()["verdict"] == "validated"
