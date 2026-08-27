"""API key authentication.

Deliberately simple: bearer tokens compared in constant time. PromptWall is
infrastructure, so it should be easy to put behind whatever real identity
system an organisation already has rather than growing its own.

Two properties that matter more than the mechanism:

  *Constant-time comparison.* A naive == on secrets leaks their prefix
  through timing, and this is exactly the kind of endpoint someone will point
  a fast client at.

  *Client keys never reach the provider.* Callers authenticate to PromptWall;
  PromptWall authenticates to the provider with its own credential. See
  UpstreamClient._headers.
"""

from __future__ import annotations

import hmac

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from ..config import fingerprint
from ..exceptions import AuthError, ForbiddenError, PromptWallError
from ..telemetry.logging import get_logger
from .error_handler import render_error

log = get_logger("http.auth")

#: Reachable without a key. Health probes must work before config is valid,
#: and metrics are expected to be scraped from inside the trust boundary.
PUBLIC_PATHS = {"/healthz", "/readyz", "/metrics", "/", "/docs", "/openapi.json", "/redoc"}


def _extract(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return request.headers.get("x-api-key", "").strip()


def _matches(candidate: str, allowed: list[str]) -> bool:
    """Constant-time membership test.

    Every key is compared even after a match so the loop's duration does not
    depend on the position of the matching key.
    """
    found = False
    for key in allowed:
        if hmac.compare_digest(candidate, key):
            found = True
    return found


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, settings) -> None:
        super().__init__(app)
        self.settings = settings

    async def dispatch(self, request: Request, call_next):
        try:
            return await self._dispatch(request, call_next)
        except PromptWallError as exc:
            # Cannot raise: see render_error in error_handler.
            return render_error(exc, getattr(request.state, "request_id", ""))

    async def _dispatch(self, request: Request, call_next):
        path = request.url.path
        if not self.settings.auth_required or path in PUBLIC_PATHS:
            request.state.principal = "anonymous"
            request.state.is_admin = not self.settings.auth_required
            return await call_next(request)

        token = _extract(request)
        if not token:
            raise AuthError("missing API key; send Authorization: Bearer <key>")

        is_admin = _matches(token, self.settings.admin_api_keys)
        if not (is_admin or _matches(token, self.settings.api_keys)):
            log.warning("rejected key", extra={"key": fingerprint(token)})
            raise AuthError("invalid API key")

        # Admin routes need an admin key specifically. A regular caller
        # reaching /admin could read policy internals and replay traffic.
        if path.startswith("/admin") and not is_admin:
            raise ForbiddenError("this endpoint requires an admin API key")

        request.state.principal = fingerprint(token)
        request.state.is_admin = is_admin
        return await call_next(request)
