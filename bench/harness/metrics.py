"""Scoring a defence.

The headline number for a prompt-injection filter is not accuracy. A corpus
that is 70% attacks makes a detector that blocks everything look 70% accurate
while being unusable.

What matters, in order:

  FPR on hard negatives  the rate at which the filter breaks legitimate
                         traffic that merely resembles an attack. This is
                         what gets a filter switched off, and it is reported
                         separately from overall FPR because averaging it
                         with easy benign traffic hides it.

  recall by family       an aggregate hides that a system catches 99% of
                         copy-pasted jailbreaks and 20% of indirect ones

  latency percentiles    p99, not mean. A gateway is judged on its tail.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Outcome:
    """One dataset record scored against one defence."""

    record_id: str
    family: str
    label: int
    predicted: int
    risk: float = 0.0
    latency_ms: float = 0.0
    decision: str = ""
    tags: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def correct(self) -> bool:
        return self.label == self.predicted


@dataclass(slots=True)
class Confusion:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def fpr(self) -> float:
        """False positive rate: benign traffic wrongly blocked."""
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0

    def add(self, outcome: Outcome) -> None:
        if outcome.label == 1:
            if outcome.predicted == 1:
                self.tp += 1
            else:
                self.fn += 1
        else:
            if outcome.predicted == 1:
                self.fp += 1
            else:
                self.tn += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "fpr": round(self.fpr, 4),
            "accuracy": round(self.accuracy, 4),
        }


def percentile(values: Sequence[float], q: float) -> float:
    """Nearest-rank percentile. No interpolation, so p99 of a small sample is
    an observed value rather than an invented one."""
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(q / 100 * len(ordered)) - 1))
    return ordered[index]


def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval.

    Reported because these corpora are small. A recall of 0.90 over 20 samples
    and one over 2000 are not the same claim, and a single number invites
    treating them as if they were.
    """
    if total == 0:
        return (0.0, 0.0)
    p = successes / total
    denom = 1 + z**2 / total
    centre = (p + z**2 / (2 * total)) / denom
    margin = z * math.sqrt(p * (1 - p) / total + z**2 / (4 * total**2)) / denom
    return (max(0.0, centre - margin), min(1.0, centre + margin))


@dataclass(slots=True)
class Results:
    """Everything measured for one defence over one corpus."""

    defence: str
    outcomes: list[Outcome] = field(default_factory=list)

    def add(self, outcome: Outcome) -> None:
        self.outcomes.append(outcome)

    @property
    def overall(self) -> Confusion:
        matrix = Confusion()
        for outcome in self.outcomes:
            matrix.add(outcome)
        return matrix

    def by_family(self) -> dict[str, Confusion]:
        out: dict[str, Confusion] = {}
        for outcome in self.outcomes:
            out.setdefault(outcome.family, Confusion()).add(outcome)
        return out

    def by_tag(self, tag: str) -> Confusion:
        matrix = Confusion()
        for outcome in self.outcomes:
            if tag in outcome.tags:
                matrix.add(outcome)
        return matrix

    @property
    def hard_negative_fpr(self) -> float:
        """The number that decides whether this is deployable."""
        matrix = self.by_tag("hard_negative")
        return matrix.fpr

    @property
    def latencies(self) -> list[float]:
        return [o.latency_ms for o in self.outcomes if not o.error]

    def latency_summary(self) -> dict[str, float]:
        values = self.latencies
        if not values:
            return {}
        return {
            "mean_ms": round(sum(values) / len(values), 3),
            "p50_ms": round(percentile(values, 50), 3),
            "p95_ms": round(percentile(values, 95), 3),
            "p99_ms": round(percentile(values, 99), 3),
            "max_ms": round(max(values), 3),
        }

    @property
    def errors(self) -> int:
        return sum(1 for o in self.outcomes if o.error)

    def missed(self) -> list[Outcome]:
        """Attacks that got through. The list to read before shipping."""
        return [o for o in self.outcomes if o.label == 1 and o.predicted == 0]

    def false_alarms(self) -> list[Outcome]:
        return [o for o in self.outcomes if o.label == 0 and o.predicted == 1]

    def to_dict(self) -> dict[str, Any]:
        matrix = self.overall
        recall_lo, recall_hi = wilson_interval(matrix.tp, matrix.tp + matrix.fn)
        fpr_lo, fpr_hi = wilson_interval(matrix.fp, matrix.fp + matrix.tn)
        return {
            "defence": self.defence,
            "samples": len(self.outcomes),
            "errors": self.errors,
            "overall": matrix.to_dict(),
            "recall_ci95": [round(recall_lo, 4), round(recall_hi, 4)],
            "fpr_ci95": [round(fpr_lo, 4), round(fpr_hi, 4)],
            "hard_negative_fpr": round(self.hard_negative_fpr, 4),
            "by_family": {name: m.to_dict() for name, m in sorted(self.by_family().items())},
            "latency": self.latency_summary(),
            "missed_ids": [o.record_id for o in self.missed()][:50],
            "false_alarm_ids": [o.record_id for o in self.false_alarms()][:50],
        }


def compare(baseline: Results, candidate: Results) -> dict[str, Any]:
    """Delta between two defences, for the CI regression gate."""
    base, cand = baseline.overall, candidate.overall
    return {
        "baseline": baseline.defence,
        "candidate": candidate.defence,
        "recall_delta": round(cand.recall - base.recall, 4),
        "fpr_delta": round(cand.fpr - base.fpr, 4),
        "f1_delta": round(cand.f1 - base.f1, 4),
        "hard_negative_fpr_delta": round(
            candidate.hard_negative_fpr - baseline.hard_negative_fpr, 4
        ),
        "newly_missed": sorted(
            {o.record_id for o in candidate.missed()} - {o.record_id for o in baseline.missed()}
        )[:50],
        "newly_caught": sorted(
            {o.record_id for o in baseline.missed()} - {o.record_id for o in candidate.missed()}
        )[:50],
    }
