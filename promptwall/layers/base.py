"""The Layer contract.

Every defence is a Layer: same interface, same error handling, same budget
accounting. That uniformity is what lets the orchestrator degrade gracefully
under load and lets the benchmark ablate any single layer to measure what it
actually contributes.

A layer must not raise. It reports findings and, where it is allowed to,
rewrites the traffic. Whether a finding becomes a block is the orchestrator's
decision against configured thresholds, never the layer's -- otherwise
thresholds would live in seven places and could not be tuned coherently.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from ..constants import LayerName, Phase
from ..exceptions import LayerError, LayerTimeout
from ..pipeline.verdict import Finding, LayerReport

if TYPE_CHECKING:
    from ..config import Settings
    from ..pipeline.context import PipelineContext


class Layer(ABC):
    """Base class for all defence layers."""

    #: Canonical identifier. Also the metrics label and the policy key.
    name: LayerName
    #: Which pipeline phase this layer belongs to.
    phase: Phase = Phase.INPUT
    #: Rough cost hint in milliseconds, used to decide whether the remaining
    #: budget can afford to run this layer at all.
    cost_ms: float = 1.0
    #: When True, a failure here is never fatal regardless of fail mode. Set
    #: on advisory layers whose absence does not weaken the guarantee.
    advisory: bool = False
    #: When True, this layer governs its own latency and is exempt from the
    #: phase affordability check. Needed for layers whose cost dwarfs the
    #: phase budget by design (the judge costs ~900ms against a 120ms input
    #: budget), where the phase check would otherwise skip them every time.
    separate_budget: bool = False

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._enabled = True

    # -- lifecycle -------------------------------------------------------

    def setup(self) -> None:  # noqa: B027 - optional hook, not abstract
        """Load models, compile patterns. Called once at startup.

        Concrete and empty on purpose: most layers need no setup, and
        making it abstract would force every subclass to write a stub.
        """

    def teardown(self) -> None:  # noqa: B027 - optional hook, not abstract
        """Release resources at shutdown. Empty by default, as above."""

    @property
    def enabled(self) -> bool:
        return self._enabled

    def disable(self, reason: str = "") -> None:
        self._enabled = False
        self._disabled_reason = reason

    # -- the actual work -------------------------------------------------

    @abstractmethod
    def run(self, ctx: PipelineContext) -> list[Finding]:
        """Inspect the context and return findings.

        Implementations may mutate ``ctx`` (that is how L0 publishes the
        normalized text and L5 publishes redacted output), but must not
        set ``ctx.verdict.decision`` directly.
        """

    def should_run(self, ctx: PipelineContext) -> tuple[bool, str]:
        """Cheap pre-check. Returning False records a skip, not a failure."""
        if not self.enabled:
            return False, getattr(self, "_disabled_reason", "disabled")
        return True, ""

    # -- orchestration entry point --------------------------------------

    def execute(self, ctx: PipelineContext) -> tuple[list[Finding], LayerReport]:
        """Run with timing, skip logic and error containment.

        The orchestrator calls this, never ``run`` directly.
        """
        report = LayerReport(layer=self.name)

        ok, reason = self.should_run(ctx)
        if not ok:
            report.ran = False
            report.skipped_reason = reason or "skipped"
            return [], report

        started = time.perf_counter()
        try:
            findings = self.run(ctx) or []
        except LayerTimeout as exc:
            report.error = "timeout"
            report.duration_ms = (time.perf_counter() - started) * 1000.0
            raise exc
        except LayerError:
            raise
        except Exception as exc:
            report.error = f"{type(exc).__name__}: {exc}"
            report.duration_ms = (time.perf_counter() - started) * 1000.0
            raise LayerError(str(self.name), report.error) from exc

        report.duration_ms = (time.perf_counter() - started) * 1000.0
        report.findings = len(findings)
        return findings, report

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} {self.name} phase={self.phase.value}>"


class NullLayer(Layer):
    """A layer that does nothing.

    Substituted for a disabled or failed-to-load layer so the pipeline shape
    stays constant. A stable shape means metrics, benchmark ablations and the
    admin replay view do not have to special-case a missing stage.
    """

    def __init__(self, settings: Settings, name: LayerName, phase: Phase, reason: str) -> None:
        super().__init__(settings)
        self.name = name
        self.phase = phase
        self.disable(reason)

    def run(self, ctx: PipelineContext) -> list[Finding]:
        return []
