"""Verdict caching.

Real traffic repeats: the same system prompt on every request, the same
retrieved document across a conversation, the same handful of user phrasings.
Re-running the full pipeline on identical input is pure waste.

Two rules keep this from becoming a vulnerability:

  the key includes the policy digest, so a policy change invalidates
  everything rather than serving decisions from a ruleset no longer in force

  only ALLOW verdicts are cached; a block is cheap to recompute and caching
  one risks serving a stale denial after policy was deliberately relaxed
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from ..constants import DEFAULT_CACHE_SIZE, DEFAULT_CACHE_TTL_S, Decision


def make_key(*parts: Any) -> str:
    """Stable cache key from arbitrary parts."""
    digest = hashlib.sha256()
    for part in parts:
        digest.update(str(part).encode("utf-8", errors="replace"))
        digest.update(b"\x00")
    return digest.hexdigest()


@dataclass(slots=True)
class _Entry:
    value: Any
    expires_at: float


class VerdictCache:
    """TTL + LRU cache, safe for concurrent use."""

    def __init__(
        self,
        max_size: int = DEFAULT_CACHE_SIZE,
        ttl_s: float = DEFAULT_CACHE_TTL_S,
    ) -> None:
        self._max = max_size
        self._ttl = ttl_s
        self._data: OrderedDict[str, _Entry] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Any | None:
        now = time.time()
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                self.misses += 1
                return None
            if entry.expires_at < now:
                del self._data[key]
                self.misses += 1
                return None
            self._data.move_to_end(key)
            self.hits += 1
            return entry.value

    def put(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = _Entry(value, time.time() + self._ttl)
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total else 0.0

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "size": len(self._data),
                "max_size": self._max,
                "ttl_s": self._ttl,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": round(self.hit_rate, 4),
            }


def cacheable(verdict) -> bool:
    """Only clean allows are worth caching. See the module docstring."""
    return (
        verdict.decision is Decision.ALLOW
        and not verdict.findings
        and not verdict.transformations
    )
