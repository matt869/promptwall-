"""L6 -- conversation-level risk.

Every other layer judges one request. L6 judges the conversation, because the
attacks that work against a deployed assistant are usually spread across
turns specifically so that no single turn looks bad enough to stop.

L6 runs last and contributes findings weighted by how much the *history*
changes the reading of the current turn. It cannot rescue a turn the earlier
layers cleared on its own merits -- it raises risk, never lowers it.
"""

from __future__ import annotations

from ..constants import AttackFamily, Decision, LayerName, Phase, Severity, TrustLevel
from ..pipeline.context import PipelineContext
from ..pipeline.verdict import Finding
from ..session import risk_score
from .base import Layer


class ConversationLayer(Layer):
    name = LayerName.L6_CONVERSATION
    phase = Phase.SESSION
    cost_ms = 1.0

    def should_run(self, ctx: PipelineContext) -> tuple[bool, str]:
        ok, reason = super().should_run(ctx)
        if not ok:
            return ok, reason
        if ctx.session is None:
            return False, "no session state (stateless request)"
        return True, ""

    def run(self, ctx: PipelineContext) -> list[Finding]:
        state = ctx.session
        assert state is not None

        turn = risk_score.turn_from_verdict(
            index=state.turn_count,
            verdict=ctx.verdict,
            had_untrusted=ctx.has_untrusted,
            tools=[call.name for call in ctx.tool_calls],
        )
        assessment = risk_score.update(state, turn)
        ctx.note("l6.session", assessment)

        findings: list[Finding] = []
        severity = risk_score.severity_for(assessment)

        if assessment.crescendo:
            findings.append(
                Finding(
                    layer=self.name,
                    rule_id="l6.crescendo",
                    message=(
                        f"risk has climbed steadily across the last "
                        f"{risk_score.CRESCENDO_WINDOW} turns "
                        f"(slope {assessment.slope:+.2f})"
                    ),
                    severity=severity,
                    family=AttackFamily.MULTITURN,
                    trust=ctx.lowest_trust,
                    source="session",
                    confidence=min(1.0, 0.5 + assessment.slope * 2),
                    weight=min(0.7, 0.25 + assessment.slope * 1.5),
                    meta={
                        "slope": assessment.slope,
                        "ewma": assessment.ewma,
                        "turns": state.turn_count,
                    },
                )
            )

        if assessment.persistent:
            findings.append(
                Finding(
                    layer=self.name,
                    rule_id="l6.persistent_probing",
                    message=(
                        f"session has been stopped {state.blocked_count} times and "
                        f"challenged {state.challenge_count} times and is still probing"
                    ),
                    severity=Severity.HIGH,
                    family=AttackFamily.MULTITURN,
                    trust=ctx.lowest_trust,
                    source="session",
                    confidence=0.9,
                    weight=0.55,
                    meta={
                        "blocked": state.blocked_count,
                        "challenged": state.challenge_count,
                    },
                )
            )
            # Persistent probing is the one case where the session itself
            # justifies stepping up, independent of this turn's content.
            ctx.verdict.raise_to(Decision.CHALLENGE)

        sticky = [f for f in assessment.flags if f.startswith("attempted_")]
        if sticky and ctx.verdict.risk > 0:
            findings.append(
                Finding(
                    layer=self.name,
                    rule_id="l6.prior_attempts",
                    message=f"session previously attempted: {', '.join(sticky)}",
                    severity=Severity.MEDIUM,
                    family=AttackFamily.MULTITURN,
                    trust=TrustLevel.THIRD_PARTY,
                    source="session",
                    confidence=0.7,
                    # Small weight on purpose. History is corroboration for a
                    # turn that already looks suspicious, not evidence on its
                    # own -- otherwise one bad turn poisons the whole session.
                    weight=0.15,
                    meta={"flags": sticky},
                )
            )

        return findings
