"""Precision/recall metrics + the detector FP corpus (real numbers, CI-gated)."""

from __future__ import annotations

from orthrus.benchmark.detectors import DISPATCH, load_corpus, run_detector_corpus
from orthrus.benchmark.metrics import ConfirmationEfficacy, ConfusionMatrix, aggregate

# --- metric math ---------------------------------------------------------------

def test_confusion_matrix_from_case():
    assert ConfusionMatrix.from_case(True, True) == ConfusionMatrix(tp=1)
    assert ConfusionMatrix.from_case(True, False) == ConfusionMatrix(fn=1)
    assert ConfusionMatrix.from_case(False, True) == ConfusionMatrix(fp=1)
    assert ConfusionMatrix.from_case(False, False) == ConfusionMatrix(tn=1)


def test_precision_recall_specificity_f1():
    m = ConfusionMatrix(tp=8, fp=2, tn=8, fn=2)
    assert m.precision == 0.8 and m.recall == 0.8 and m.specificity == 0.8
    assert round(m.f1, 4) == 0.8
    assert m.accuracy == 0.8


def test_no_predictions_is_precision_one_not_zero_division():
    m = ConfusionMatrix(tp=0, fp=0, tn=5, fn=0)
    assert m.precision == 1.0 and m.recall == 1.0 and m.specificity == 1.0


def test_aggregate_sums_matrices():
    total = aggregate([ConfusionMatrix(tp=1, fp=1), ConfusionMatrix(tp=2, tn=3)])
    assert total == ConfusionMatrix(tp=3, fp=1, tn=3)


def test_confirmation_efficacy_models_the_thesis():
    # detection-only had 2 false positives; confirmation dropped both, kept all TPs.
    pre = ConfusionMatrix(tp=3, fp=2)
    post = ConfusionMatrix(tp=3, fp=0)
    eff = ConfirmationEfficacy(pre=pre, post=post)
    assert eff.false_positives_removed == 2
    assert eff.true_positives_kept == 1.0
    assert eff.precision_before == 0.6 and eff.precision_after == 1.0
    assert eff.precision_gain == 0.4


# --- the real corpus: run the actual detectors, gate on zero false positives ---

def test_every_corpus_case_targets_a_known_detector():
    unknown = {c.get("detector") for c in load_corpus()} - set(DISPATCH)
    assert unknown == set(), f"corpus references unknown detectors: {unknown}"


def test_detector_corpus_has_no_false_positives_or_misses():
    """Regression gate: if a scanner starts over-firing on clean input (FP) or
    misses a known-vulnerable input (FN), this fails - the number the researcher
    asked for, enforced in CI."""
    per, agg, errors = run_detector_corpus()
    assert errors == [], f"detector raised on a corpus input: {errors}"
    assert agg.fp == 0, f"false positive(s) on clean input: {agg.as_dict()}"
    assert agg.fn == 0, f"missed known-vulnerable input(s): {agg.as_dict()}"
    for name, m in per.items():
        assert m.precision == 1.0, f"{name} precision dropped: {m.as_dict()}"


def test_corpus_is_balanced_enough_to_be_meaningful():
    # A precision number is only meaningful with real clean cases to fire on.
    _per, agg, _err = run_detector_corpus()
    assert agg.tp >= 15 and agg.tn >= 15, f"corpus too small/imbalanced: {agg.as_dict()}"
