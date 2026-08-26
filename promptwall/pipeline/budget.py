"""Latency budgets.

A security gateway that adds unpredictable latency gets removed from the
request path, so the budget is a real security control rather than a
performance nicety: it is what keeps PromptWall deployed.

The rule is that layers are ordered cheapest-and-most-decisive first, so
running out of budget degrades detection gracefully instead of arbitrarily.
Whatever did run has already produced its findings.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..constants import Phase


@dataclass(slots=True)
class Budget:
    """Tracks spend for one phase of one request."""

    phase: Phase
    limit_ms: float
    started: float = field(default_factory=time.perf_counter)
    #: Layers skipped because the remaining budget could not afford them.
    skipped: list[str] = field(default_factory=list)

    @property
    def spent_ms(self) -> float:
        return (time.perf_counter() - self.started) * 1000.0

    @property
    def remaining_ms(self) -> float:
        return max(0.0, self.limit_ms - self.spent_ms)

    @property
    def exhausted(self) -> bool:
        return self.spent_ms >= self.limit_ms

    def can_afford(self, cost_ms: float) -> bool:
        """Is there room for a layer of roughly this cost?

        Uses the layer's declared cost rather than measuring after the fact,
        because discovering the overrun afterwards is exactly the outcome the
        budget exists to prevent.
        """
        return self.remaining_ms >= cost_ms

    def skip(self, layer: str) -> None:
        self.skipped.append(layer)

    def to_dict(self) -> dict[str, object]:
        return {
            "phase": self.phase.value,
            "limit_ms": self.limit_ms,
            "spent_ms": round(self.spent_ms, 3),
            "skipped": self.skipped,
        }


def for_phase(settings, phase: Phase) -> Budget:
    limits = {
        Phase.INPUT: settings.budgets.input_ms,
        Phase.TOOL: settings.budgets.input_ms,
        Phase.OUTPUT: settings.budgets.output_ms,
        Phase.SESSION: settings.budgets.output_ms,
    }
    return Budget(phase=phase, limit_ms=limits.get(phase, settings.budgets.input_ms))
