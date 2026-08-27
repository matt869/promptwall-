"""The orchestrator: runs layers, enforces budgets, decides the outcome.

This is the only place that turns findings into a decision. Layers report;
the orchestrator judges. Keeping that split means thresholds live in one
place and can be tuned coherently, and it is what makes the benchmark's
layer-ablation runs meaningful.

Two behaviours are worth reading carefully:

  fail mode   what happens when a layer errors. Default is fail-open, which
              is the right default for availability and the wrong one for a
              high-assurance deployment. See docs/adr/003.

  monitor     the pipeline computes everything and marks the verdict
              advisory instead of acting. Nobody should turn on enforcement
              without first seeing what it would have blocked.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from ..constants import Decision, Phase
from ..exceptions import BudgetExhausted, LayerError
from ..policy.engine import PolicyEngine
from ..taint.tracker import flatten, track_messages
from .budget import Budget, for_phase
from .cache import VerdictCache, cacheable, make_key
from .context import PipelineContext, ToolCall
from .verdict import LayerReport, Verdict

if TYPE_CHECKING:
    from ..config import Settings
    from ..layers.registry import LayerRegistry
    from ..policy.loader import PolicyStore
    from ..session.store import SessionStore

log = logging.getLogger("promptwall.pipeline")


class Pipeline:
    """Owns the layers, the policy store and the caches for a process."""

    def __init__(
        self,
        settings: Settings,
        registry: LayerRegistry,
        policy_store: PolicyStore,
        session_store: SessionStore | None = None,
        cache: VerdictCache | None = None,
    ) -> None:
        self.settings = settings
        self.registry = registry
        self.policy_store = policy_store
        self.session_store = session_store
        self.cache = cache if cache is not None else VerdictCache()

    # -- engine ----------------------------------------------------------

    def engine(self) -> PolicyEngine:
        """A PolicyEngine over the currently active bundle.

        Rebuilt per call rather than cached, so a policy reload takes effect
        on the next request without any invalidation dance. Construction is
        just binding a reference; the expensive part is the compiled-pattern
        cache, which lives on the engine and is warmed on first use.
        """
        return PolicyEngine(self.policy_store.bundle)

    # -- public entry points ---------------------------------------------

    def inspect_request(
        self,
        messages: Sequence[dict[str, Any]],
        *,
        session_id: str = "",
        request_id: str = "",
        tools: Sequence[dict[str, Any]] | None = None,
    ) -> PipelineContext:
        """Run the INPUT phase over an incoming request."""
        ctx = self._context(Phase.INPUT, session_id=session_id, request_id=request_id)
        ctx.messages = track_messages(messages)
        ctx.raw_text, ctx.raw_taint = flatten(ctx.messages)
        ctx.system_prompt = "\n".join(
            m.text for m in ctx.messages if m.role.lower() in {"system", "developer"}
        )
        if tools:
            ctx.note("declared_tools", [t.get("name") or t.get("function", {}).get("name") for t in tools])

        cache_key = make_key("input", self.policy_store.bundle.digest, ctx.raw_text)
        cached = self.cache.get(cache_key)
        if cached is not None:
            ctx.verdict = cached
            ctx.verdict.request_id = ctx.request_id
            ctx.note("cache", "hit")
            return ctx

        self._run_phase(ctx, Phase.INPUT)
        self._finalize(ctx)
        if cacheable(ctx.verdict):
            self.cache.put(cache_key, ctx.verdict)
        return ctx

    def inspect_tool_calls(
        self, ctx: PipelineContext, calls: Sequence[ToolCall]
    ) -> PipelineContext:
        """Run the TOOL phase. Reuses the input context so L4 sees its findings."""
        ctx.phase = Phase.TOOL
        ctx.verdict.phase = Phase.TOOL
        ctx.tool_calls = list(calls)
        self._run_phase(ctx, Phase.TOOL)
        self._finalize(ctx)
        return ctx

    def inspect_response(
        self,
        output: str,
        *,
        ctx: PipelineContext | None = None,
        system_prompt: str = "",
        session_id: str = "",
        request_id: str = "",
    ) -> PipelineContext:
        """Run the OUTPUT phase over a model response."""
        if ctx is None:
            ctx = self._context(Phase.OUTPUT, session_id=session_id, request_id=request_id)
            ctx.system_prompt = system_prompt
        else:
            ctx.phase = Phase.OUTPUT
            ctx.verdict.phase = Phase.OUTPUT
        ctx.output_text = output
        self._run_phase(ctx, Phase.OUTPUT)
        self._finalize(ctx)
        return ctx

    def close_turn(self, ctx: PipelineContext) -> PipelineContext:
        """Run the SESSION phase and persist the updated session state."""
        if not ctx.session_id or self.session_store is None:
            return ctx
        ctx.phase = Phase.SESSION
        ctx.verdict.phase = Phase.SESSION
        ctx.session = self._load_session(ctx.session_id)
        self._run_phase(ctx, Phase.SESSION)
        self._finalize(ctx)
        if ctx.session is not None:
            self.session_store.put(ctx.session)
        return ctx

    # -- internals -------------------------------------------------------

    def _context(self, phase: Phase, *, session_id: str, request_id: str) -> PipelineContext:
        bundle = self.policy_store.bundle
        verdict = Verdict(phase=phase, policy_digest=bundle.digest, policy_version=bundle.version)
        ctx = PipelineContext(
            settings=self.settings,
            engine=self.engine(),
            phase=phase,
            session_id=session_id,
            verdict=verdict,
        )
        if request_id:
            ctx.request_id = request_id
            ctx.verdict.request_id = request_id
        return ctx

    def _load_session(self, session_id: str):
        if self.session_store is None:
            return None
        state = self.session_store.get(session_id)
        if state is None:
            from ..session.store import SessionState

            state = SessionState(session_id=session_id)
        return state

    def _run_phase(self, ctx: PipelineContext, phase: Phase) -> None:
        """Execute every layer for a phase, under one shared budget."""
        budget = for_phase(self.settings, phase)
        ctx.note(f"budget.{phase.value}", budget)

        for layer in self.registry.for_phase(phase):
            if budget.exhausted and not layer.separate_budget:
                budget.skip(str(layer.name))
                ctx.verdict.record(
                    LayerReport(
                        layer=layer.name,
                        ran=False,
                        skipped_reason=f"budget exhausted after {budget.spent_ms:.0f}ms",
                    )
                )
                continue

            if not layer.separate_budget and not budget.can_afford(layer.cost_ms):
                budget.skip(str(layer.name))
                ctx.verdict.record(
                    LayerReport(
                        layer=layer.name,
                        ran=False,
                        skipped_reason=(
                            f"needs ~{layer.cost_ms:.0f}ms, "
                            f"{budget.remaining_ms:.0f}ms remaining"
                        ),
                    )
                )
                continue

            self._run_layer(ctx, layer, budget)

        if budget.skipped:
            ctx.note(f"budget.{phase.value}.skipped", budget.skipped)

    def _run_layer(self, ctx: PipelineContext, layer, budget: Budget) -> None:
        try:
            findings, report = layer.execute(ctx)
        except (LayerError, BudgetExhausted) as exc:
            report = LayerReport(
                layer=layer.name, ran=False, error=str(exc), duration_ms=0.0
            )
            ctx.verdict.record(report)
            self._handle_failure(ctx, layer, exc)
            return
        except Exception as exc:
            log.exception("layer %s raised an unhandled exception", layer.name)
            ctx.verdict.record(
                LayerReport(layer=layer.name, ran=False, error=f"{type(exc).__name__}: {exc}")
            )
            self._handle_failure(ctx, layer, exc)
            return

        ctx.verdict.record(report)
        ctx.verdict.add(*findings)

    def _handle_failure(self, ctx: PipelineContext, layer, exc: Exception) -> None:
        """Apply the configured fail mode to a layer that did not complete.

        Advisory layers are exempt: the judge being unreachable degrades
        detection quality but does not weaken the taint-tracking and tool-gate
        guarantees, so failing a request closed over it would trade a real
        outage for a hypothetical attack.
        """
        log.warning("layer %s failed: %s", layer.name, exc)
        if getattr(layer, "advisory", False):
            ctx.note(f"degraded.{layer.name}", str(exc))
            return
        if self.settings.fail_closed:
            ctx.verdict.raise_to(Decision.BLOCK)
            ctx.note("fail_closed", str(layer.name))
        else:
            ctx.note(f"degraded.{layer.name}", str(exc))

    def _finalize(self, ctx: PipelineContext) -> None:
        ctx.verdict.finalize(
            thresholds=self.settings.thresholds,
            enforcing=self.settings.enforcing,
        )

    # -- introspection ---------------------------------------------------

    def status(self) -> dict[str, Any]:
        return {
            "mode": self.settings.mode.value,
            "fail_mode": self.settings.fail_mode.value,
            "layers": self.registry.status(),
            "degraded": self.registry.degraded,
            "policy": self.policy_store.status(),
            "cache": self.cache.stats(),
            "sessions": (
                self.session_store.stats() if self.session_store is not None else None
            ),
        }


def build_pipeline(settings: Settings) -> Pipeline:
    """Construct a fully wired pipeline. The normal entry point."""
    from ..layers.registry import build_registry
    from ..policy.loader import get_store
    from ..session.store import build_store

    return Pipeline(
        settings=settings,
        registry=build_registry(settings),
        policy_store=get_store(settings.policy_dir or None),
        session_store=build_store(settings),
    )
