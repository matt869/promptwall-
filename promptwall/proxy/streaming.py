"""Guarding a streaming response.

The hard constraint: bytes already sent cannot be recalled. A secret split
across two SSE chunks is invisible to any guard that inspects chunks
independently, and by the time the second chunk reveals it, the first is
already in the client's buffer.

So the guard holds back a tail. Text is released only once enough following
context exists that a pattern spanning the boundary would already have been
seen. HOLD_CHARS is that safety margin, and it is a direct latency-versus-
safety trade: larger means more of a secret can never escape, and more delay
before the user sees each token.

The residual risk is honest and worth stating: a leak shorter than the hold
window is caught, a slow drip engineered to stay under it across a very long
response is not. Non-streaming requests get the full guarantee, which is why
PW_STREAMING_GUARD can be set to require buffering for sensitive routes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Callable

#: Characters withheld from the client until enough context follows them.
#: Comfortably longer than the longest credential pattern in redaction.yaml.
HOLD_CHARS = 256

#: Re-scan cadence. Scanning on every token is wasteful; this bounds how much
#: new text can accumulate before the guard looks again.
SCAN_INTERVAL_CHARS = 64

_DONE = "[DONE]"


@dataclass(slots=True)
class StreamStats:
    events: int = 0
    text_chars: int = 0
    redactions: int = 0
    blocked: bool = False
    block_reason: str = ""


@dataclass(slots=True)
class SSEParser:
    """Incremental Server-Sent Events parser.

    Chunk boundaries fall anywhere, including mid-event, so the parser keeps
    a byte buffer and only emits complete events.
    """

    buffer: bytes = b""
    events: list[tuple[str, str]] = field(default_factory=list)

    def feed(self, chunk: bytes) -> list[tuple[str, str]]:
        """Add bytes, return any (event_name, data) pairs now complete."""
        self.buffer += chunk
        out: list[tuple[str, str]] = []

        while b"\n\n" in self.buffer:
            raw, self.buffer = self.buffer.split(b"\n\n", 1)
            event_name = ""
            data_lines: list[str] = []
            for line in raw.decode("utf-8", errors="replace").splitlines():
                if line.startswith("event:"):
                    event_name = line[6:].strip()
                elif line.startswith("data:"):
                    data_lines.append(line[5:].lstrip())
            if data_lines:
                out.append((event_name, "\n".join(data_lines)))
        return out

    def flush(self) -> list[tuple[str, str]]:
        """Emit any trailing event left without a terminating blank line."""
        if not self.buffer.strip():
            return []
        remaining, self.buffer = self.buffer, b""
        return self.feed(remaining + b"\n\n")


def format_sse(data: str, event: str = "") -> bytes:
    prefix = f"event: {event}\n" if event else ""
    return f"{prefix}data: {data}\n\n".encode()


class StreamGuard:
    """Applies the output guard to a live SSE stream.

    Usage is a single pass: feed upstream chunks in, get guarded chunks out.
    The guard owns the decision to cut the stream short.
    """

    def __init__(
        self,
        provider,
        guard: Callable[[str], tuple[str, bool, str]],
        *,
        hold_chars: int = HOLD_CHARS,
    ) -> None:
        self.provider = provider
        #: text -> (guarded_text, should_block, reason)
        self.guard = guard
        self.hold = hold_chars
        self.parser = SSEParser()
        self.stats = StreamStats()

        #: Text accumulated but not yet released to the client.
        self._pending = ""
        #: Everything released so far, for whole-response checks at the end.
        self._released = ""
        self._since_scan = 0
        self._queued: list[dict[str, Any]] = []

    async def process(self, upstream: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
        """Transform an upstream byte stream into a guarded one."""
        async for chunk in upstream:
            for event_name, data in self.parser.feed(chunk):
                async for out in self._handle(event_name, data):
                    yield out
                if self.stats.blocked:
                    return

        for event_name, data in self.parser.flush():
            async for out in self._handle(event_name, data):
                yield out
            if self.stats.blocked:
                return

        # Release whatever is still held, after a final full-text scan.
        async for out in self._drain():
            yield out

    async def _handle(self, event_name: str, data: str) -> AsyncIterator[bytes]:
        self.stats.events += 1

        if data.strip() == _DONE:
            async for out in self._drain():
                yield out
            yield format_sse(_DONE)
            return

        try:
            event = json.loads(data)
        except json.JSONDecodeError:
            # Not JSON we understand. Pass it through rather than dropping a
            # provider control frame we do not recognise.
            yield format_sse(data, event_name)
            return

        delta = self.provider.stream_text_delta(event)
        if not delta:
            yield format_sse(json.dumps(event, ensure_ascii=False), event_name)
            return

        self._pending += delta
        self.stats.text_chars += len(delta)
        self._since_scan += len(delta)

        releasable = self._releasable()
        if releasable and self._since_scan >= SCAN_INTERVAL_CHARS:
            self._since_scan = 0
            guarded, blocked, reason = self.guard(self._released + releasable)
            if blocked:
                self.stats.blocked = True
                self.stats.block_reason = reason
                yield self._block_event(reason)
                return
            # The guard sees the whole response so far; only the newly
            # releasable tail of its output is ours to emit now.
            new_text = guarded[len(self._released) :]
            if new_text != releasable:
                self.stats.redactions += 1
            self._released += new_text
            self._pending = self._pending[len(releasable) :]
            yield format_sse(
                json.dumps(
                    self.provider.rewrite_stream_delta(event, new_text), ensure_ascii=False
                ),
                event_name,
            )
            return

        # Nothing safe to release yet: hold this delta back entirely.
        self._queued.append(event)

    def _releasable(self) -> str:
        """The prefix of pending text that is far enough from the frontier."""
        if len(self._pending) <= self.hold:
            return ""
        return self._pending[: len(self._pending) - self.hold]

    async def _drain(self) -> AsyncIterator[bytes]:
        """Final scan over the complete response, then release the tail."""
        if not self._pending:
            return
        guarded, blocked, reason = self.guard(self._released + self._pending)
        if blocked:
            self.stats.blocked = True
            self.stats.block_reason = reason
            yield self._block_event(reason)
            return

        tail = guarded[len(self._released) :]
        if tail != self._pending:
            self.stats.redactions += 1
        self._released += tail
        self._pending = ""
        template = self._queued[-1] if self._queued else {}
        yield format_sse(
            json.dumps(
                self.provider.rewrite_stream_delta(dict(template) or {}, tail),
                ensure_ascii=False,
            )
        )

    def _block_event(self, reason: str) -> bytes:
        """Terminate the stream with an error the client can surface.

        Cutting the connection without explanation would look like a network
        fault and get retried; an explicit error frame does not.
        """
        return format_sse(
            json.dumps(
                {
                    "error": {
                        "type": "blocked_by_policy",
                        "message": "PromptWall stopped this response mid-stream.",
                        "reason": reason,
                    }
                },
                ensure_ascii=False,
            ),
            "error",
        )
