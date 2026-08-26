"""Turning exceptions into responses.

One rule: an unexpected exception never reaches the client as a stack trace
or an internal message. PromptWall sits in front of an LLM provider and sees
credentials, prompts and policy internals, all of which leak readily through
careless error text.

Known PromptWallErrors carry their own status and a message written to be
seen. Everything else becomes an opaque 500 whose only useful content is the
request id, which the operator can join against the log.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from ..constants import HEADER_REQUEST_ID
from ..exceptions import PromptWallError, RateLimitedError
from ..telemetry.logging import get_logger

log = get_logger("http.errors")


def render_error(exc: PromptWallError, request_id: str = "") -> JSONResponse:
    """Render a PromptWallError as a response.

    Shared with the middleware, which cannot simply raise. Starlette's
    ExceptionMiddleware sits *inside* the user middleware stack, so an
    exception raised in middleware sails past every handler registered on the
    app and surfaces as an unhandled 500. Middleware must therefore return
    this rather than raise.
    """
    body = exc.to_dict()
    if request_id:
        body["error"]["request_id"] = request_id

    headers = {HEADER_REQUEST_ID: request_id} if request_id else {}
    if isinstance(exc, RateLimitedError):
        headers["retry-after"] = str(max(1, int(exc.retry_after_s)))
    return JSONResponse(status_code=exc.status_code, content=body, headers=headers)


def install(app: FastAPI) -> None:
    """Register the exception handlers."""

    @app.exception_handler(PromptWallError)
    async def _promptwall(request: Request, exc: PromptWallError) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "")
        level = log.warning if exc.status_code < 500 else log.error
        level(
            "handled error",
            extra={"code": exc.code, "status": exc.status_code, "detail": exc.message},
        )
        return render_error(exc, request_id)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "")
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "type": "invalid_request",
                    "message": "Request body failed validation.",
                    "details": exc.errors()[:10],
                    "request_id": request_id,
                }
            },
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "")
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "type": "http_error",
                    "message": str(exc.detail),
                    "request_id": request_id,
                }
            },
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "")
        # Full detail to the log, nothing to the client.
        log.exception("unhandled exception", extra={"path": request.url.path})
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "type": "internal_error",
                    "message": "An internal error occurred.",
                    "request_id": request_id,
                }
            },
        )
