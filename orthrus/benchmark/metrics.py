"""Precision / recall / confirmation-efficacy metrics (pure, offline).

The existing :mod:`scorer` measures *detection rate* (recall) and an
"unexpected findings" false-positive *proxy*. That proves ORTHRUS finds known
vulnerabilities; it does not prove it stays quiet on safe code - the measurement
a reviewer actually wants before trusting an automated (let alone AI-assisted)
scanner.

This module supplies the missing half: a proper confusion matrix (TP/FP/TN/FN)
computed against a corpus that contains both **vulnerable** and **known-clean**
cases, and from it precision, recall, specificity and F1. It also models
**confirmation efficacy** - how ORTHRUS's confirmation phase changes precision,
which is the whole thesis ("confirm, don't just flag") reduced to a number.

Pure and dependency-free so the numbers are deterministic and reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ConfusionMatrix:
    """Counts for a binary detector over labelled cases.

    * **tp** - vulnerable case, detector fired (correct)
    * **fp** - clean case, detector fired (a false positive - the thing to minimise)
    * **tn** - clean case, detector stayed quiet (correct)
    * **fn** - vulnerable case, detector missed it
    """

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    def __add__(self, other: ConfusionMatrix) -> ConfusionMatrix:
        return ConfusionMatrix(
            self.tp + other.tp, self.fp + other.fp, self.tn + other.tn, self.fn + other.fn
        )

    @classmethod
    def from_case(cls, should_fire: bool, fired: bool) -> ConfusionMatrix:
        if should_fire and fired:
            return cls(tp=1)
        if should_fire and not fired:
            return cls(fn=1)
        if not should_fire and fired:
            return cls(fp=1)
        return cls(tn=1)

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def predicted_positive(self) -> int:
        return self.tp + self.fp

    @property
    def precision(self) -> float:
        """TP / (TP + FP). 1.0 when nothing was flagged (no false alarms)."""
        return self.tp / self.predicted_positive if self.predicted_positive else 1.0

    @property
    def recall(self) -> float:
        """TP / (TP + FN). 1.0 when there was nothing to find."""
        denom = self.tp + self.fn
        return self.tp / denom if denom else 1.0

    @property
    def specificity(self) -> float:
        """TN / (TN + FP): how reliably the detector stays quiet on clean input."""
        denom = self.tn + self.fp
        return self.tn / denom if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 1.0

    def as_dict(self) -> dict[str, float | int]:
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn, "total": self.total,
            "precision": round(self.precision, 4), "recall": round(self.recall, 4),
            "specificity": round(self.specificity, 4), "f1": round(self.f1, 4),
        }


@dataclass(frozen=True)
class ConfirmationEfficacy:
    """How the confirmation phase changed the outcome (the ORTHRUS thesis, measured).

    ``pre`` is the detection-only confusion matrix; ``post`` is after confirmation
    re-proved (and dropped) findings. Good confirmation removes false positives
    while keeping true positives.
    """

    pre: ConfusionMatrix
    post: ConfusionMatrix

    @property
    def false_positives_removed(self) -> int:
        return max(0, self.pre.fp - self.post.fp)

    @property
    def true_positives_kept(self) -> float:
        return self.post.tp / self.pre.tp if self.pre.tp else 1.0

    @property
    def precision_before(self) -> float:
        return round(self.pre.precision, 4)

    @property
    def precision_after(self) -> float:
        return round(self.post.precision, 4)

    @property
    def precision_gain(self) -> float:
        return round(self.post.precision - self.pre.precision, 4)

    def as_dict(self) -> dict[str, float | int]:
        return {
            "false_positives_removed": self.false_positives_removed,
            "true_positives_kept": round(self.true_positives_kept, 4),
            "precision_before": self.precision_before,
            "precision_after": self.precision_after,
            "precision_gain": self.precision_gain,
        }


def aggregate(matrices: list[ConfusionMatrix]) -> ConfusionMatrix:
    total = ConfusionMatrix()
    for m in matrices:
        total = total + m
    return total


__all__ = ["ConfusionMatrix", "ConfirmationEfficacy", "aggregate"]
