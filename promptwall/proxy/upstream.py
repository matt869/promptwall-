"""Talking to the model provider.

One shared async client per process. Connection pooling matters more than
usual here: PromptWall adds a hop to every request, and a fresh TLS handshake
per call would dominate the latency budget the layers are being so careful
about.

Retries are narrow on purpose. Only idempotent failures -- connection errors,
timeouts before any byte arrived, 429 and 5xx -- are retried. Anything that
reached the model and came back is returned as-is, because silently retrying
a request the provider already billed and possibly acted on is worse than an
error the caller can see.
"""

from __future__ import annotations

import asyncio
import contextlib
import json as _json
import random
import time
from collections.abc import AsyncIterator
from typing import Any

import httpx

from ..exceptions import UpstreamError, UpstreamTimeout
from ..telemetry.logging import get_logger
from ..telemetry.metrics import get_metrics

log = get_logger("proxy.upstream")

#: Status codes worth retrying: 408/429 and 5xx only.
_RETRYABLE = {408, 429, 500, 502, 503, 504}

#: Hop-by-hop headers that must not be forwarded in either direction.
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length",
    "content-encoding", "host",
}


def _provider_message(response: httpx.Response, body: bytes | None = None) -> str:
    """Surface the provider's own error text without leaking our credentials."""
    try:
        data = _json.loads(body) if body is not None else response.json()
        if isinstance(data, dict):
            error = data.get("error")
            if isinstance(error, dict) and error.get("message"):
                return f"provider error: {error['message']}"[:500]
            if isinstance(error, str):
                return f"provider error: {error}"[:500]
    except Exception:
        pass
    return f"provider returned HTTP {response.status_code}"


class UpstreamClient:
    """Async HTTP client for one configured provider."""

    def __init__(self, settings) -> None:
        self.settings = settings
        cfg = settings.upstream
        self._client = httpx.AsyncClient(
            base_url=cfg.base_url,
            timeout=httpx.Timeout(cfg.timeout_s, connect=10.0),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            follow_redirects=False,
        )
        self._max_retries = cfg.max_retries

    async def aclose(self) -> None:
        await self._client.aclose()

    def _headers(self, incoming: dict[str, str] | None = None) -> dict[str, str]:
        """Build upstream headers.

        The caller's Authorization is deliberately NOT forwarded. Clients
        authenticate to PromptWall with a PromptWall key; PromptWall
        authenticates to the provider with its own. Relaying the caller's
        header would make the gateway a credential pass-through and defeat
        the point of terminating auth here.
        """
        cfg = self.settings.upstream
        headers: dict[str, str] = {"content-type": "application/json"}

        for key, value in (incoming or {}).items():
            low = key.lower()
            if low in _HOP_BY_HOP or low in {"authorization", "x-api-key", "cookie"}:
                continue
            if low.startswith(("x-promptwall", "accept-encoding")):
                continue
            headers[low] = value

        if cfg.provider == "anthropic":
            headers["x-api-key"] = cfg.api_key
            headers.setdefault("anthropic-version", "2023-06-01")
        else:
            headers["authorization"] = f"Bearer {cfg.api_key}"
        return headers

    async def _backoff(self, attempt: int, response: httpx.Response | None) -> None:
        """Exponential backoff, honouring Retry-After, with jitter.

        Jitter is not decoration: without it every instance behind a load
        balancer retries in lockstep and turns a provider blip into a
        synchronised stampede.
        """
        delay = min(8.0, 0.25 * (2**attempt))
        if response is not None:
            header = response.headers.get("retry-after")
            if header:
                with contextlib.suppress(ValueError):
                    delay = min(30.0, float(header))
        await asyncio.sleep(delay * (0.5 + random.random()))

    async def _send(
        self, path: str, payload: dict[str, Any], headers: dict[str, str] | None
    ) -> httpx.Response:
        attempt = 0
        last_error: Exception | None = None

        while attempt <= self._max_retries:
            try:
                response = await self._client.post(
                    path, json=payload, headers=self._headers(headers)
                )
                if response.status_code in _RETRYABLE and attempt < self._max_retries:
                    await self._backoff(attempt, response)
                    attempt += 1
                    continue
                return response
            except httpx.TimeoutException as exc:
                last_error = exc
                if attempt >= self._max_retries:
                    raise UpstreamTimeout(
                        f"provider did not respond within {self.settings.upstream.timeout_s}s"
                    ) from exc
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt >= self._max_retries:
                    raise UpstreamError(f"could not reach provider: {exc}") from exc
            await self._backoff(attempt, None)
            attempt += 1

        raise UpstreamError(f"provider request failed: {last_error}")

    def _echo(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Synthesise a reply without calling anyone.

        Lets someone run the gateway and watch it work before they have a
        provider account, and gives the demo and smoke test something
        deterministic to talk to. It echoes what the model *would* have
        received, which also makes spotlighting visible.
        """
        messages = payload.get("messages") or []
        last = ""
        for message in reversed(messages):
            if str(message.get("role", "")) == "user":
                content = message.get("content")
                last = content if isinstance(content, str) else str(content)
                break
        return {
            "id": "chatcmpl-echo",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": payload.get("model", "echo"),
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": (
                            "[echo provider] PromptWall forwarded "
                            f"{len(messages)} message(s). Last user turn: {last[:400]}"
                        ),
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }

    async def post_json(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """POST and parse a JSON response, with bounded retries."""
        if self.settings.upstream.provider == "echo":
            return self._echo(payload)
        started = time.perf_counter()
        outcome = "error"
        try:
            response = await self._send(path, payload, headers)
            outcome = (
                "ok" if response.status_code < 400 else f"http_{response.status_code // 100}xx"
            )
            if response.status_code >= 400:
                raise UpstreamError(
                    _provider_message(response), upstream_status=response.status_code
                )
            try:
                return response.json()
            except ValueError as exc:
                raise UpstreamError("provider returned a non-JSON response") from exc
        finally:
            get_metrics().record_upstream(
                self.settings.upstream.provider, outcome, time.perf_counter() - started
            )

    async def stream(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
    ) -> AsyncIterator[bytes]:
        """Open a streaming response. Never retried once bytes are flowing."""
        request = self._client.build_request(
            "POST", path, json=payload, headers=self._headers(headers)
        )
        response = await self._client.send(request, stream=True)
        if response.status_code >= 400:
            body = await response.aread()
            await response.aclose()
            raise UpstreamError(
                _provider_message(response, body), upstream_status=response.status_code
            )
        try:
            async for chunk in response.aiter_bytes():
                yield chunk
        finally:
            await response.aclose()


_client: UpstreamClient | None = None


def get_client(settings) -> UpstreamClient:
    global _client
    if _client is None:
        _client = UpstreamClient(settings)
    return _client


async def close_client() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None
