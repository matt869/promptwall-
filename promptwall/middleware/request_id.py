"""Request correlation.

Every request gets an id before anything else can fail, so the log line for a
crash and the audit record for the verdict can always be joined. The id is
echoed on the response because callers reporting a false positive need
something to quote.

An inbound id is honoured but sanitised: it ends up in log files and headers,
so it is length-capped and restricted to a safe alphabet rather than trusted.
"""

from __future__ import annotations

import re
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from ..constants import HEADER_REQUEST_ID
from ..telemetry.logging import bind, get_logger

log = get_logger("http")

_SAFE_ID = re.compile(r"[^A-Za-z0-9._:-]")
MAX_ID_LEN = 64


def _clean(candidate: str) -> str:
    return _SAFE_ID.sub("", candidate)[:MAX_ID_LEN]


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        incoming = _clean(request.headers.get(HEADER_REQUEST_ID, ""))
        request_id = incoming or uuid.uuid4().hex[:16]
        request.state.request_id = request_id
        bind(request_id=request_id)

        started = time.perf_counter()
        try:
            response: Response = await call_next(request)
        except Exception:
            elapsed = (time.perf_counter() - started) * 1000
            log.exception(
                "request failed",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "duration_ms": round(elapsed, 2),
                },
            )
            raise

        elapsed = (time.perf_counter() - started) * 1000
        response.headers[HEADER_REQUEST_ID] = request_id
        if request.url.path not in {"/healthz", "/readyz", "/metrics"}:
            log.info(
                "request",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "status": response.status_code,
                    "duration_ms": round(elapsed, 2),
                },
            )
        return response
