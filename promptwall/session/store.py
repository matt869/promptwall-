"""Conversation state across turns.

Single-turn defence is not enough. The effective attacks against a deployed
assistant are incremental: establish a persona, get a small concession, widen
it, and only then ask for the thing that matters. Every individual turn looks
defensible, which is exactly the point.

Storing state makes that visible, and it is also what makes rate-limiting a
*conversation* rather than a connection possible.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..constants import Decision

#: Turns retained per session. Enough to see a crescendo develop without
#: turning the store into an unbounded transcript archive.
MAX_TURN_HISTORY = 40


@dataclass(slots=True)
class TurnRecord:
    """One evaluated turn, reduced to what cross-turn analysis needs."""

    index: int
    risk: float
    decision: str
    families: list[str] = field(default_factory=list)
    had_untrusted: bool = False
    tool_calls: list[str] = field(default_factory=list)
    at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "risk": round(self.risk, 4),
            "decision": self.decision,
            "families": self.families,
            "had_untrusted": self.had_untrusted,
            "tool_calls": self.tool_calls,
            "at": round(self.at, 3),
        }


@dataclass(slots=True)
class SessionState:
    """Accumulated view of one conversation."""

    session_id: str
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    turns: list[TurnRecord] = field(default_factory=list)

    #: Exponentially weighted risk. Recent turns dominate, but history does
    #: not vanish the moment an attacker sends one innocuous message.
    ewma_risk: float = 0.0
    #: Highest risk seen. Never decays: a session that once tried something
    #: serious stays notable for the rest of its life.
    peak_risk: float = 0.0
    blocked_count: int = 0
    challenge_count: int = 0
    #: Sticky markers, e.g. "attempted_exfiltration".
    flags: set[str] = field(default_factory=set)

    @property
    def turn_count(self) -> int:
        return len(self.turns)

    @property
    def age_s(self) -> float:
        return time.time() - self.created_at

    def recent(self, n: int = 5) -> list[TurnRecord]:
        return self.turns[-n:]

    def record(self, turn: TurnRecord) -> None:
        self.turns.append(turn)
        if len(self.turns) > MAX_TURN_HISTORY:
            del self.turns[: len(self.turns) - MAX_TURN_HISTORY]
        self.updated_at = time.time()
        if turn.decision == Decision.BLOCK.value:
            self.blocked_count += 1
        elif turn.decision == Decision.CHALLENGE.value:
            self.challenge_count += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "turns": self.turn_count,
            "age_s": round(self.age_s, 1),
            "ewma_risk": round(self.ewma_risk, 4),
            "peak_risk": round(self.peak_risk, 4),
            "blocked": self.blocked_count,
            "challenged": self.challenge_count,
            "flags": sorted(self.flags),
        }


class SessionStore(Protocol):
    def get(self, session_id: str) -> SessionState | None: ...
    def put(self, state: SessionState) -> None: ...
    def delete(self, session_id: str) -> None: ...
    def stats(self) -> dict[str, Any]: ...


class MemorySessionStore:
    """In-process store with TTL and LRU eviction.

    Correct for a single instance and for development. Behind more than one
    replica, sessions bind to whichever instance served them, so cross-turn
    detection degrades silently -- use the Redis backend there.
    """

    def __init__(self, ttl_s: int = 3600, max_sessions: int = 10_000) -> None:
        self._ttl = ttl_s
        self._max = max_sessions
        self._data: OrderedDict[str, SessionState] = OrderedDict()
        self._lock = threading.Lock()
        self._evictions = 0

    def get(self, session_id: str) -> SessionState | None:
        with self._lock:
            state = self._data.get(session_id)
            if state is None:
                return None
            if time.time() - state.updated_at > self._ttl:
                del self._data[session_id]
                return None
            self._data.move_to_end(session_id)
            return state

    def put(self, state: SessionState) -> None:
        with self._lock:
            self._data[state.session_id] = state
            self._data.move_to_end(state.session_id)
            while len(self._data) > self._max:
                self._data.popitem(last=False)
                self._evictions += 1

    def delete(self, session_id: str) -> None:
        with self._lock:
            self._data.pop(session_id, None)

    def purge_expired(self) -> int:
        cutoff = time.time() - self._ttl
        with self._lock:
            stale = [k for k, v in self._data.items() if v.updated_at < cutoff]
            for key in stale:
                del self._data[key]
            return len(stale)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "backend": "memory",
                "sessions": len(self._data),
                "evictions": self._evictions,
                "ttl_s": self._ttl,
            }


def build_store(settings) -> SessionStore:
    """Construct the configured store, degrading loudly rather than silently."""
    cfg = settings.session
    if cfg.backend == "redis":
        try:
            from .redis_store import RedisSessionStore

            return RedisSessionStore(cfg.redis_url, ttl_s=cfg.ttl_s)
        except ImportError:
            import logging

            logging.getLogger("promptwall.session").warning(
                "PW_SESSION_BACKEND=redis but the redis package is not installed; "
                "falling back to in-memory sessions. Cross-turn detection will be "
                "unreliable across replicas."
            )
    return MemorySessionStore(ttl_s=cfg.ttl_s)
