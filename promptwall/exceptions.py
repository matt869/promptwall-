"""Exception hierarchy.

Everything raised deliberately by PromptWall descends from :class:`PromptWallError`
and carries an HTTP status plus a stable machine-readable ``code``, so the error
middleware can render a consistent response body without a big isinstance ladder.
"""

from __future__ import annotations

from typing import Any


class PromptWallError(Exception):
    """Base class. Subclasses set ``status_code`` and ``code``."""

    status_code: int = 500
    code: str = "internal_error"

    def __init__(self, message: str, **details: Any) -> None:
        super().__init__(message)
        self.message = message
        self.details = details

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {"error": {"type": self.code, "message": self.message}}
        if self.details:
            body["error"]["details"] = self.details
        return body

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"{type(self).__name__}({self.message!r}, {self.details!r})"


# --- Configuration ----------------------------------------------------------


class ConfigError(PromptWallError):
    """Bad or missing configuration. Fatal at startup, never at request time."""

    status_code = 500
    code = "config_error"


class PolicyError(PromptWallError):
    status_code = 500
    code = "policy_error"


class PolicyValidationError(PolicyError):
    """A rules file failed schema validation. Includes the offending path."""

    code = "policy_validation_error"


class PolicyNotFoundError(PolicyError):
    status_code = 404
    code = "policy_not_found"


# --- Pipeline ---------------------------------------------------------------


class LayerError(PromptWallError):
    """A layer raised. Handled per the configured fail mode, not propagated."""

    code = "layer_error"

    def __init__(self, layer: str, message: str, **details: Any) -> None:
        super().__init__(message, layer=layer, **details)
        self.layer = layer


class LayerTimeout(LayerError):
    code = "layer_timeout"


class BudgetExhausted(PromptWallError):
    """The phase ran out of its latency budget. Remaining layers are skipped."""

    code = "budget_exhausted"

    def __init__(self, phase: str, spent_ms: float, budget_ms: float) -> None:
        super().__init__(
            f"{phase} phase exhausted its {budget_ms:.0f}ms budget after {spent_ms:.1f}ms",
            phase=phase,
            spent_ms=round(spent_ms, 2),
            budget_ms=budget_ms,
        )
        self.phase = phase


# --- Request handling -------------------------------------------------------


class BlockedError(PromptWallError):
    """Request refused by policy. The only 'expected' 4xx we raise on purpose."""

    status_code = 403
    code = "blocked_by_policy"

    def __init__(self, message: str, verdict: Any = None, **details: Any) -> None:
        super().__init__(message, **details)
        self.verdict = verdict

    def to_dict(self) -> dict[str, Any]:
        body = super().to_dict()
        if self.verdict is not None and hasattr(self.verdict, "to_client_dict"):
            body["error"]["promptwall"] = self.verdict.to_client_dict()
        return body


class AuthError(PromptWallError):
    status_code = 401
    code = "unauthorized"


class ForbiddenError(PromptWallError):
    status_code = 403
    code = "forbidden"


class RateLimitedError(PromptWallError):
    status_code = 429
    code = "rate_limited"

    def __init__(self, message: str, retry_after_s: float = 1.0, **details: Any) -> None:
        super().__init__(message, retry_after_s=round(retry_after_s, 3), **details)
        self.retry_after_s = retry_after_s


class ValidationError(PromptWallError):
    status_code = 422
    code = "invalid_request"


class PayloadTooLargeError(PromptWallError):
    status_code = 413
    code = "payload_too_large"


# --- Upstream ---------------------------------------------------------------


class UpstreamError(PromptWallError):
    """The model provider failed. ``upstream_status`` is echoed when useful."""

    status_code = 502
    code = "upstream_error"

    def __init__(self, message: str, upstream_status: int | None = None, **details: Any) -> None:
        if upstream_status is not None:
            details["upstream_status"] = upstream_status
        super().__init__(message, **details)
        self.upstream_status = upstream_status


class UpstreamTimeout(UpstreamError):
    status_code = 504
    code = "upstream_timeout"
