"""Findings: what a layer or rule noticed.

Lives at the top level rather than inside ``pipeline`` because both the
policy engine and the pipeline need it, and importing it from ``pipeline``
made ``policy -> pipeline -> orchestrator -> policy`` a cycle. Its only
dependency is ``constants``, so nothing can import it into a loop.

A Finding keeps its span and trust level rather than collapsing to a score at
the point of detection, because the same matched text means very different
things depending on where it came from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .constants import (
    SEVERITY_WEIGHT,
    AttackFamily,
    LayerName,
    Severity,
    TrustLevel,
)


@dataclass(slots=True)
class Finding:
    """One thing a layer noticed."""

    layer: LayerName | str
    rule_id: str
    message: str
    severity: Severity = Severity.MEDIUM
    family: AttackFamily = AttackFamily.NONE

    #: Location in the text the layer was given. -1 when not span-based.
    start: int = -1
    end: int = -1
    #: Same span mapped back to what the caller actually sent.
    orig_start: int = -1
    orig_end: int = -1

    #: Lowest trust inside the span. The single most important qualifier on a
    #: finding: identical text means very different things in a system prompt
    #: and in a fetched web page.
    trust: TrustLevel = TrustLevel.UNTRUSTED
    source: str = ""

    #: 0..1. For rule hits this is the rule's weight; for the classifier it
    #: is the calibrated probability.
    confidence: float = 1.0
    #: Contribution to the aggregate risk score. None means "derive it from
    #: severity"; an explicit 0.0 means "this finding must not raise risk",
    #: which is what a *mitigated* issue reports. Conflating the two made a
    #: successfully redacted secret block the response it had just made safe.
    weight: float | None = None

    #: Short excerpt, only populated when content logging is enabled.
    excerpt: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.weight is None:
            self.weight = SEVERITY_WEIGHT[self.severity] * max(0.0, min(1.0, self.confidence))

    @property
    def in_untrusted(self) -> bool:
        return self.trust <= TrustLevel.THIRD_PARTY

    def to_dict(self, *, include_excerpt: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "layer": str(self.layer),
            "rule_id": self.rule_id,
            "message": self.message,
            "severity": self.severity.value,
            "family": self.family.value,
            "trust": self.trust.name.lower(),
            "confidence": round(self.confidence, 4),
            "weight": round(self.weight, 4),
        }
        if self.start >= 0:
            data["span"] = [self.start, self.end]
        if self.orig_start >= 0:
            data["orig_span"] = [self.orig_start, self.orig_end]
        if self.source:
            data["source"] = self.source
        if include_excerpt and self.excerpt:
            data["excerpt"] = self.excerpt
        if self.meta:
            data["meta"] = self.meta
        return data


def aggregate_risk(findings: list[Finding]) -> float:
    """Combine finding weights into a 0..1 risk score.

    Noisy-OR rather than a sum or a max. Summing lets a pile of low-severity
    noise outrank one critical hit; taking the max throws away the
    corroborating evidence that distinguishes a real attack from an unlucky
    phrase. Noisy-OR saturates toward 1 while letting independent weak
    signals reinforce each other.
    """
    survival = 1.0
    for finding in findings:
        survival *= 1.0 - max(0.0, min(1.0, finding.weight))
    return round(1.0 - survival, 6)
