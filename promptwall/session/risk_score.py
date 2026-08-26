"""Cross-turn risk scoring.

Turns a sequence of per-turn verdicts into a view of the conversation. The
design question is what to do with time, and there are two wrong answers:

  forget immediately   an attacker resets by sending one innocuous message
  never forget         every long conversation eventually trips the threshold

So risk decays, but the *peak* does not, and specific behaviours leave sticky
flags. A session that once tried to exfiltrate data is permanently more
interesting than one that never did, even if its recent turns are calm.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..constants import AttackFamily, Decision, Severity
from .store import SessionState, TurnRecord

#: Weight of the newest turn in the EWMA. High enough to react within a few
#: turns, low enough that one benign message does not launder the history.
EWMA_ALPHA = 0.4

#: A rising trend across this many turns is treated as a crescendo.
CRESCENDO_WINDOW = 4
CRESCENDO_MIN_SLOPE = 0.08

#: Families that leave a permanent mark on the session.
STICKY_FAMILIES = {
    AttackFamily.EXFILTRATION: "attempted_exfiltration",
    AttackFamily.TOOL_ABUSE: "attempted_tool_abuse",
    AttackFamily.SYSPROMPT_LEAK: "attempted_prompt_extraction",
    AttackFamily.INSTRUCTION_OVERRIDE: "attempted_override",
}


@dataclass(slots=True)
class SessionRisk:
    """The cross-turn assessment for one request."""

    ewma: float = 0.0
    peak: float = 0.0
    crescendo: bool = False
    slope: float = 0.0
    persistent: bool = False
    flags: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.flags is None:
            self.flags = []

    @property
    def elevated(self) -> bool:
        return self.crescendo or self.persistent or self.ewma >= 0.5


def update(state: SessionState, turn: TurnRecord) -> SessionRisk:
    """Fold one turn into the session and return the resulting assessment."""
    state.record(turn)

    state.ewma_risk = (
        turn.risk
        if state.turn_count == 1
        else EWMA_ALPHA * turn.risk + (1 - EWMA_ALPHA) * state.ewma_risk
    )
    state.peak_risk = max(state.peak_risk, turn.risk)

    for family_name in turn.families:
        try:
            family = AttackFamily(family_name)
        except ValueError:
            continue
        flag = STICKY_FAMILIES.get(family)
        if flag:
            state.flags.add(flag)

    slope = _slope([t.risk for t in state.recent(CRESCENDO_WINDOW)])
    crescendo = (
        state.turn_count >= CRESCENDO_WINDOW
        and slope >= CRESCENDO_MIN_SLOPE
        and state.ewma_risk >= 0.25
    )
    if crescendo:
        state.flags.add("crescendo")

    # Repeated refusals are a stronger signal than any single turn: ordinary
    # users do not get blocked three times and keep rephrasing.
    persistent = state.blocked_count >= 2 or (
        state.blocked_count + state.challenge_count >= 4
    )
    if persistent:
        state.flags.add("persistent_probing")

    return SessionRisk(
        ewma=round(state.ewma_risk, 4),
        peak=round(state.peak_risk, 4),
        crescendo=crescendo,
        slope=round(slope, 4),
        persistent=persistent,
        flags=sorted(state.flags),
    )


def _slope(values: list[float]) -> float:
    """Least-squares slope over the recent risk series.

    A plain first-vs-last comparison is trivially defeated by alternating a
    high turn with a low one; a fitted slope is not.
    """
    n = len(values)
    if n < 2:
        return 0.0
    mean_x = (n - 1) / 2
    mean_y = sum(values) / n
    numerator = sum((i - mean_x) * (v - mean_y) for i, v in enumerate(values))
    denominator = sum((i - mean_x) ** 2 for i in range(n))
    return numerator / denominator if denominator else 0.0


def severity_for(risk: SessionRisk) -> Severity:
    if risk.persistent or risk.ewma >= 0.75:
        return Severity.HIGH
    if risk.crescendo or risk.ewma >= 0.5:
        return Severity.MEDIUM
    return Severity.LOW


def turn_from_verdict(index: int, verdict, had_untrusted: bool, tools: list[str]) -> TurnRecord:
    return TurnRecord(
        index=index,
        risk=verdict.risk,
        decision=verdict.decision.value
        if isinstance(verdict.decision, Decision)
        else str(verdict.decision),
        families=verdict.families,
        had_untrusted=had_untrusted,
        tool_calls=tools,
    )
