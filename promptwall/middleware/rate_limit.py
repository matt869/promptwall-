"""Per-principal rate limiting.

A token bucket keyed by API key (falling back to client address). Bursts are
allowed because LLM traffic is naturally bursty; the sustained rate is what
gets enforced.

This protects the gateway itself, not the provider's quota. The layers do
real work per request -- regex scanning, feature extraction, sometimes a
judge call -- so an unthrottled client can exhaust CPU here long before it
troubles the model provider.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from ..exceptions import RateLimitedError
from .error_handler import render_error

EXEMPT_PATHS = {"/healthz", "/readyz", "/metrics"}
MAX_BUCKETS = 50_000


@dataclass(slots=True)
class Bucket:
    tokens: float
    updated: float


class TokenBucketLimiter:
    """Classic token bucket with lazy refill."""

    def __init__(self, rate_per_s: float, burst: int) -> None:
        self.rate = rate_per_s
        self.burst = float(burst)
        self._buckets: OrderedDict[str, Bucket] = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, key: str, cost: float = 1.0) -> tuple[bool, float]:
        """Returns (allowed, retry_after_seconds)."""
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = Bucket(tokens=self.burst, updated=now)
                self._buckets[key] = bucket
                # Bound memory: an attacker rotating keys must not be able to
                # grow this map without limit.
                while len(self._buckets) > MAX_BUCKETS:
                    self._buckets.popitem(last=False)
            else:
                self._buckets.move_to_end(key)
                elapsed = now - bucket.updated
                bucket.tokens = min(self.burst, bucket.tokens + elapsed * self.rate)
                bucket.updated = now

            if bucket.tokens >= cost:
                bucket.tokens -= cost
                return True, 0.0
            deficit = cost - bucket.tokens
            return False, deficit / self.rate if self.rate > 0 else 1.0

    def stats(self) -> dict[str, object]:
        with self._lock:
            return {"buckets": len(self._buckets), "rate": self.rate, "burst": self.burst}


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, settings) -> None:
        super().__init__(app)
        self.limiter = TokenBucketLimiter(settings.rate_limit_rps, settings.rate_limit_burst)

    async def dispatch(self, request: Request, call_next):
        if request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        key = getattr(request.state, "principal", "") or (
            request.client.host if request.client else "unknown"
        )
        allowed, retry_after = self.limiter.allow(key)
        if not allowed:
            # Cannot raise: see render_error in error_handler.
            return render_error(
                RateLimitedError("rate limit exceeded", retry_after_s=retry_after),
                getattr(request.state, "request_id", ""),
            )

        response = await call_next(request)
        response.headers["x-ratelimit-limit"] = str(int(self.limiter.burst))
        return response
