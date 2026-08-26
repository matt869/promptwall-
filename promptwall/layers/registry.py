"""Layer registration and construction.

The canonical order lives in ``constants.LAYER_ORDER`` and is not negotiable
at runtime. Ordering is a security property here, not a preference: L0 must
normalize before L1 matches, and L4 must be able to see what L1-L3 concluded
before it authorizes a tool call. See docs/adr/001-layer-ordering.md.

A layer that fails to construct becomes a NullLayer rather than an exception,
so the pipeline keeps a constant shape and the failure shows up in the
readiness probe instead of as a 500 on the first request.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Callable

from ..constants import LAYER_ORDER, LayerName, Phase
from .base import Layer, NullLayer
from .l0_normalize import NormalizeLayer
from .l1_heuristics import HeuristicsLayer
from .l2_classifier import ClassifierLayer
from .l3_judge import JudgeLayer
from .l4_tool_gate import ToolGateLayer
from .l5_output_guard import OutputGuardLayer
from .l6_conversation import ConversationLayer

if TYPE_CHECKING:
    from ..config import Settings

log = logging.getLogger("promptwall.layers")

#: The only place layer classes are named. Adding a layer means adding it
#: here and to LAYER_ORDER, and nowhere else.
LAYER_CLASSES: dict[LayerName, type[Layer]] = {
    LayerName.L0_NORMALIZE: NormalizeLayer,
    LayerName.L1_HEURISTICS: HeuristicsLayer,
    LayerName.L2_CLASSIFIER: ClassifierLayer,
    LayerName.L3_JUDGE: JudgeLayer,
    LayerName.L4_TOOL_GATE: ToolGateLayer,
    LayerName.L5_OUTPUT_GUARD: OutputGuardLayer,
    LayerName.L6_CONVERSATION: ConversationLayer,
}

_PHASES: dict[LayerName, Phase] = {
    name: cls.phase for name, cls in LAYER_CLASSES.items()
}


class LayerRegistry:
    """Constructed layers, indexed by name and grouped by phase."""

    def __init__(self, settings: "Settings", *, only: list[LayerName] | None = None) -> None:
        self.settings = settings
        self._layers: dict[LayerName, Layer] = {}
        self._build(only)

    def _build(self, only: list[LayerName] | None) -> None:
        selected = set(only) if only is not None else set(LAYER_ORDER)
        for name in LAYER_ORDER:
            cls = LAYER_CLASSES[name]
            if name not in selected:
                self._layers[name] = NullLayer(
                    self.settings, name, _PHASES[name], "not selected"
                )
                continue
            try:
                layer = cls(self.settings)
                layer.setup()
                self._layers[name] = layer
            except Exception as exc:  # noqa: BLE001 - startup must not abort
                log.error("layer %s failed to initialize: %s", name, exc, exc_info=True)
                self._layers[name] = NullLayer(
                    self.settings, name, _PHASES[name], f"init failed: {exc}"
                )

    # -- access ----------------------------------------------------------

    def get(self, name: LayerName) -> Layer:
        return self._layers[name]

    def for_phase(self, phase: Phase) -> list[Layer]:
        """Layers for a phase, in canonical order."""
        return [self._layers[n] for n in LAYER_ORDER if self._layers[n].phase is phase]

    def all(self) -> list[Layer]:
        return [self._layers[n] for n in LAYER_ORDER]

    def enabled(self) -> list[Layer]:
        return [layer for layer in self.all() if layer.enabled]

    def teardown(self) -> None:
        for layer in self._layers.values():
            try:
                layer.teardown()
            except Exception:  # noqa: BLE001
                log.warning("layer %s raised during teardown", layer.name, exc_info=True)

    def status(self) -> dict[str, dict[str, object]]:
        """Per-layer health, surfaced by /healthz and the admin API."""
        return {
            str(name): {
                "enabled": layer.enabled,
                "phase": layer.phase.value,
                "class": type(layer).__name__,
                "reason": getattr(layer, "_disabled_reason", ""),
            }
            for name, layer in self._layers.items()
        }

    @property
    def degraded(self) -> bool:
        """True when a layer that should be running is not.

        The judge is excluded: it is off by default and its absence is a cost
        decision, not a fault.
        """
        return any(
            not layer.enabled
            for name, layer in self._layers.items()
            if name is not LayerName.L3_JUDGE
        )


def build_registry(settings: "Settings", **kwargs) -> LayerRegistry:
    return LayerRegistry(settings, **kwargs)
