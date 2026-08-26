"""Structured logging.

JSON by default because these logs are meant to be queried, not read. A
human-readable console format is available for development.

The important rule here is that prompt content never reaches the application
log. An LLM gateway sees every prompt its users send, which makes its log a
high-value target and a data-protection liability. Content goes to the audit
log, which is separately configured and off by default; everything else gets
identifiers and counts.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from contextvars import ContextVar
from typing import Any

#: Correlates every log line emitted while handling one request.
request_id_var: ContextVar[str] = ContextVar("request_id", default="")
session_id_var: ContextVar[str] = ContextVar("session_id", default="")

#: Never emitted, even if a caller passes them as extras.
_REDACT_KEYS = {
    "authorization", "api_key", "apikey", "password", "secret", "token",
    "content", "messages", "prompt", "text", "body",
}

_RESERVED = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "asctime", "taskName",
}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        request_id = request_id_var.get()
        if request_id:
            payload["request_id"] = request_id
        session_id = session_id_var.get()
        if session_id:
            payload["session_id"] = session_id

        for key, value in record.__dict__.items():
            if key in _RESERVED or key.startswith("_"):
                continue
            payload[key] = "[redacted]" if key.lower() in _REDACT_KEYS else _safe(value)

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


class ConsoleFormatter(logging.Formatter):
    """Compact human format for local development."""

    def format(self, record: logging.LogRecord) -> str:
        stamp = time.strftime("%H:%M:%S", time.localtime(record.created))
        request_id = request_id_var.get()
        prefix = f"[{request_id[:8]}] " if request_id else ""
        base = f"{stamp} {record.levelname:<7} {record.name:<24} {prefix}{record.getMessage()}"
        if record.exc_info:
            base += "\n" + self.formatException(record.exc_info)
        return base


def _safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    if isinstance(value, (list, tuple)):
        return [_safe(v) for v in value][:50]
    if isinstance(value, dict):
        return {k: ("[redacted]" if k.lower() in _REDACT_KEYS else _safe(v))
                for k, v in list(value.items())[:50]}
    return str(value)


def configure(level: str = "INFO", fmt: str = "json") -> None:
    """Install the root handler. Idempotent."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if fmt == "json" else ConsoleFormatter())
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # uvicorn duplicates access logs through its own handlers.
    for noisy in ("uvicorn.access", "uvicorn.error", "httpx", "httpcore"):
        logging.getLogger(noisy).handlers = []
        logging.getLogger(noisy).propagate = True
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"promptwall.{name}" if not name.startswith("promptwall") else name)


def bind(request_id: str = "", session_id: str = "") -> None:
    if request_id:
        request_id_var.set(request_id)
    if session_id:
        session_id_var.set(session_id)
