"""Session state and cross-turn risk."""

from __future__ import annotations

import pytest

from promptwall.constants import AttackFamily
from promptwall.session import risk_score
from promptwall.session.store import MemorySessionStore, SessionState, TurnRecord


def turn(index: int, risk: float, decision: str = "allow", families=None) -> TurnRecord:
    return TurnRecord(
        index=index, risk=risk, decision=decision, families=families or []
    )


class TestMemoryStore:
    def test_round_trip(self):
        store = MemorySessionStore(ttl_s=60)
        state = SessionState(session_id="s1")
        store.put(state)
        assert store.get("s1") is state
        store.delete("s1")
        assert store.get("s1") is None

    def test_lru_eviction_is_bounded(self):
        """An attacker rotating session ids must not grow the map without limit."""
        store = MemorySessionStore(ttl_s=60, max_sessions=3)
        for i in range(10):
            store.put(SessionState(session_id=f"s{i}"))
        assert store.stats()["sessions"] == 3
        assert store.get("s0") is None
        assert store.get("s9") is not None

    def test_expiry(self):
        """Backdate rather than sleep: a timing-dependent test is a flaky test."""
        store = MemorySessionStore(ttl_s=60)
        state = SessionState(session_id="s1")
        store.put(state)
        assert store.get("s1") is not None

        state.updated_at -= 61
        assert store.get("s1") is None

    def test_purge_expired_reclaims(self):
        store = MemorySessionStore(ttl_s=60)
        for i in range(3):
            state = SessionState(session_id=f"s{i}")
            state.updated_at -= 61
            store.put(state)
        assert store.purge_expired() == 3
        assert store.stats()["sessions"] == 0


class TestRiskScoring:
    def test_peak_never_decays_but_ewma_does(self):
        """A session that once tried something serious stays notable."""
        state = SessionState(session_id="s")
        risk_score.update(state, turn(0, 0.9))
        peak = state.peak_risk
        for i in range(1, 6):
            risk_score.update(state, turn(i, 0.0))
        assert state.peak_risk == peak
        assert state.ewma_risk < peak

    def test_crescendo_needs_a_rising_trend(self):
        rising = SessionState(session_id="up")
        for i, r in enumerate([0.1, 0.3, 0.5, 0.7]):
            assessment = risk_score.update(rising, turn(i, r))
        assert assessment.crescendo
        assert assessment.slope > 0

        flat = SessionState(session_id="flat")
        for i in range(4):
            assessment = risk_score.update(flat, turn(i, 0.05))
        assert not assessment.crescendo

    def test_alternating_turns_do_not_hide_the_trend(self):
        """A fitted slope resists the obvious evasion that first-vs-last does not."""
        state = SessionState(session_id="zigzag")
        for i, r in enumerate([0.1, 0.0, 0.4, 0.0, 0.7, 0.9]):
            assessment = risk_score.update(state, turn(i, r))
        assert assessment.slope > 0

    def test_repeated_blocks_flag_persistent_probing(self):
        state = SessionState(session_id="s")
        for i in range(2):
            assessment = risk_score.update(state, turn(i, 0.95, decision="block"))
        assert assessment.persistent
        assert "persistent_probing" in state.flags

    def test_attack_families_leave_sticky_flags(self):
        state = SessionState(session_id="s")
        risk_score.update(
            state, turn(0, 0.9, families=[AttackFamily.EXFILTRATION.value])
        )
        for i in range(1, 5):
            risk_score.update(state, turn(i, 0.0))
        assert "attempted_exfiltration" in state.flags

    def test_history_is_bounded(self):
        state = SessionState(session_id="s")
        for i in range(200):
            risk_score.update(state, turn(i, 0.1))
        assert state.turn_count <= 40


class TestRedisStore:
    """Serialization and failure behaviour. No server required."""

    @pytest.fixture(autouse=True)
    def _require_redis(self):
        pytest.importorskip("redis", reason="redis client not installed")

    def test_round_trip_is_faithful(self):
        from promptwall.session.redis_store import _dumps, _loads

        state = SessionState(session_id="abc")
        state.flags.update({"crescendo", "attempted_exfiltration"})
        state.ewma_risk, state.peak_risk = 0.42, 0.91
        state.blocked_count, state.challenge_count = 2, 3
        for i in range(4):
            state.record(
                TurnRecord(index=i, risk=0.1 * i, decision="allow", families=["indirect"])
            )

        back = _loads(_dumps(state))
        assert back is not None
        assert back.session_id == state.session_id
        assert back.flags == state.flags
        assert back.peak_risk == pytest.approx(state.peak_risk)
        assert back.blocked_count == state.blocked_count
        assert back.turn_count == state.turn_count
        assert back.turns[-1].families == ["indirect"]

    @pytest.mark.parametrize(
        "blob",
        ['{"v":999,"session_id":"x"}', "{not json", '["a","list"]', ""],
    )
    def test_unreadable_records_are_discarded_not_coerced(self, blob):
        """A schema change must not resurrect old state as something subtly wrong."""
        from promptwall.session.redis_store import _loads

        assert _loads(blob) is None

    def test_unreachable_redis_degrades_without_raising(self):
        """Refusing traffic because a cache is down trades a real outage for a
        hypothetical attack. See ADR 003."""
        from promptwall.session.redis_store import RedisSessionStore

        store = RedisSessionStore("redis://127.0.0.1:6399/0", ttl_s=60, socket_timeout=0.2)
        assert store.get("nobody") is None
        store.put(SessionState(session_id="s"))
        store.delete("s")
        assert store.stats()["errors"] >= 2
        assert store.stats()["healthy"] is False
