"""Redis-backed session store.

Needed as soon as there is more than one replica. The in-process store binds
a conversation to whichever instance served its first turn, so behind a load
balancer the turns of one conversation scatter and L6 sees a fragment of each.
Nothing errors; cross-turn detection just quietly stops working, which is why
the shipped compose and Kubernetes configs both select this backend.

Two behaviours worth reading:

*Redis failures degrade, they do not fail requests.* A read error is reported
as "no session", so the turn is evaluated on its own merits and cross-turn
analysis is skipped for it. Refusing traffic because a cache is unreachable
would trade a real outage for a hypothetical attack, which is the same
reasoning as ADR 003.

*State is versioned.* A schema change must not make old records deserialise
into something subtly wrong, so records carrying an unknown version are
discarded rather than coerced.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from .store import MAX_TURN_HISTORY, SessionState, TurnRecord

log = logging.getLogger("promptwall.session")

#: Bumped whenever the serialised shape changes. Records written by another
#: version are dropped, not migrated in place.
STATE_VERSION = 1

KEY_PREFIX = "promptwall:session:"


def _dumps(state: SessionState) -> str:
    return json.dumps(
        {
            "v": STATE_VERSION,
            "session_id": state.session_id,
            "created_at": state.created_at,
            "updated_at": state.updated_at,
            "ewma_risk": state.ewma_risk,
            "peak_risk": state.peak_risk,
            "blocked_count": state.blocked_count,
            "challenge_count": state.challenge_count,
            # A set is not JSON-serialisable; sorted for a stable payload.
            "flags": sorted(state.flags),
            "turns": [t.to_dict() for t in state.turns[-MAX_TURN_HISTORY:]],
        },
        separators=(",", ":"),
    )


def _loads(blob: str | bytes) -> SessionState | None:
    try:
        data = json.loads(blob)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(data, dict) or data.get("v") != STATE_VERSION:
        return None

    try:
        state = SessionState(
            session_id=str(data["session_id"]),
            created_at=float(data.get("created_at", 0.0)),
            updated_at=float(data.get("updated_at", 0.0)),
            ewma_risk=float(data.get("ewma_risk", 0.0)),
            peak_risk=float(data.get("peak_risk", 0.0)),
            blocked_count=int(data.get("blocked_count", 0)),
            challenge_count=int(data.get("challenge_count", 0)),
            flags=set(data.get("flags", [])),
        )
        state.turns = [
            TurnRecord(
                index=int(t.get("index", 0)),
                risk=float(t.get("risk", 0.0)),
                decision=str(t.get("decision", "allow")),
                families=list(t.get("families", [])),
                had_untrusted=bool(t.get("had_untrusted", False)),
                tool_calls=list(t.get("tool_calls", [])),
                at=float(t.get("at", 0.0)),
            )
            for t in data.get("turns", [])
        ]
    except (KeyError, TypeError, ValueError):
        return None
    return state


class RedisSessionStore:
    """SessionStore backed by Redis. Import fails if `redis` is not installed."""

    def __init__(self, url: str, *, ttl_s: int = 3600, socket_timeout: float = 0.5) -> None:
        import redis

        self._ttl = ttl_s
        # Short timeouts on purpose. This sits in the request path, and a
        # slow session lookup must not become the gateway's latency profile.
        self._client = redis.Redis.from_url(
            url,
            socket_timeout=socket_timeout,
            socket_connect_timeout=socket_timeout,
            decode_responses=True,
            health_check_interval=30,
        )
        self._errors = 0
        self._reads = 0
        self._writes = 0

    @staticmethod
    def _key(session_id: str) -> str:
        return f"{KEY_PREFIX}{session_id}"

    def get(self, session_id: str) -> SessionState | None:
        self._reads += 1
        try:
            blob = self._client.get(self._key(session_id))
        except Exception as exc:
            self._errors += 1
            log.warning("session read failed, continuing without history: %s", exc)
            return None
        if blob is None:
            return None

        state = _loads(blob)
        if state is None:
            # Unreadable or written by another schema version. Drop it rather
            # than risk resurrecting it as something subtly wrong.
            log.info("discarding unreadable session record")
            self.delete(session_id)
        return state

    def put(self, state: SessionState) -> None:
        self._writes += 1
        try:
            # Refresh the TTL on every write, so an active conversation stays
            # alive and an abandoned one expires on its own.
            self._client.set(self._key(state.session_id), _dumps(state), ex=self._ttl)
        except Exception as exc:
            self._errors += 1
            log.warning("session write failed, cross-turn state not persisted: %s", exc)

    def delete(self, session_id: str) -> None:
        try:
            self._client.delete(self._key(session_id))
        except Exception as exc:
            self._errors += 1
            log.warning("session delete failed: %s", exc)

    def ping(self) -> bool:
        try:
            return bool(self._client.ping())
        except Exception:
            return False

    def stats(self) -> dict[str, Any]:
        return {
            "backend": "redis",
            "ttl_s": self._ttl,
            "reads": self._reads,
            "writes": self._writes,
            "errors": self._errors,
            "healthy": self.ping(),
        }
