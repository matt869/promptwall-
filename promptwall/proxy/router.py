"""The proxy endpoints.

This is where the pipeline meets the network. The shape of a guarded request:

    inspect input  ->  (block?)  ->  spotlight  ->  upstream
                                                       |
    caller  <-  guard output  <-  gate tool calls  <----+

Two things are deliberate.

*The pipeline runs in a worker thread.* L0-L2 are CPU-bound regex and feature
work. Running them on the event loop would stall every other in-flight
request for the duration, which on a gateway is the whole point of failure.

*Spotlighting happens after inspection, not before.* The layers need to see
what the caller actually sent; the model needs to see it fenced. Doing it the
other way round would have the detectors analysing our own scaffolding.
"""

from __future__ import annotations

import json
from typing import Any

from anyio import to_thread
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from ..constants import (
    HEADER_DECISION,
    HEADER_REQUEST_ID,
    HEADER_RISK,
    HEADER_SESSION,
    Decision,
)
from ..exceptions import BlockedError, PayloadTooLargeError, ValidationError
from ..pipeline.context import ToolCall
from ..proxy.providers import get_provider
from ..proxy.schemas import BlockedResponse
from ..proxy.streaming import StreamGuard
from ..proxy.upstream import get_client
from ..taint.spotlight import SpotlightMode
from ..taint.spotlight import apply as spotlight_apply
from ..taint.spotlight import preamble
from ..telemetry.logging import bind, get_logger
from ..telemetry.metrics import get_metrics
from ..telemetry.tracing import annotate_verdict, span

log = get_logger("proxy.router")
router = APIRouter()


def _state(request: Request):
    """The app-scoped singletons, attached during lifespan startup."""
    return request.app.state.settings, request.app.state.pipeline


async def _body(request: Request, limit: int) -> dict[str, Any]:
    raw = await request.body()
    if len(raw) > limit:
        raise PayloadTooLargeError(
            f"request body is {len(raw)} bytes, over the {limit} byte limit"
        )
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"request body is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValidationError("request body must be a JSON object")
    return payload


def _session_id(request: Request, payload: dict[str, Any]) -> str:
    return str(
        payload.get("pw_session_id")
        or request.headers.get(HEADER_SESSION)
        or payload.get("user")
        or ""
    )


def _decision_headers(verdict) -> dict[str, str]:
    """Advertise the verdict on every response, including allows.

    Callers running in monitor mode need to see what *would* have happened
    without parsing the audit log, and clients that want to fail closed on
    their own can key off these.
    """
    return {
        HEADER_REQUEST_ID: verdict.request_id,
        HEADER_DECISION: verdict.decision.value,
        HEADER_RISK: f"{verdict.risk:.4f}",
    }


def _spotlight_payload(payload: dict[str, Any], ctx, mode: SpotlightMode) -> dict[str, Any]:
    """Fence untrusted messages and teach the model the convention.

    Applied per message rather than to the flattened prompt, so the provider's
    own message structure survives. The preamble is appended to the system
    message because a convention the model was never told about is no
    convention at all.
    """
    if mode is SpotlightMode.NONE or not ctx.messages:
        return payload

    messages = payload.get("messages")
    if not isinstance(messages, list):
        return payload

    fenced = 0
    for tracked in ctx.messages:
        if tracked.index >= len(messages):
            continue
        if tracked.trust > ctx.settings.spotlight_floor:
            continue
        result = spotlight_apply(tracked.text, tracked.taint, mode, ctx.settings.spotlight_floor)
        if result.regions:
            messages[tracked.index] = {
                **messages[tracked.index],
                "content": result.text,
            }
            fenced += result.regions

    if fenced:
        note = preamble(mode)
        system_index = next(
            (i for i, m in enumerate(messages)
             if str(m.get("role", "")).lower() in {"system", "developer"}),
            None,
        )
        if system_index is None:
            messages.insert(0, {"role": "system", "content": note})
        else:
            existing = messages[system_index].get("content") or ""
            messages[system_index] = {
                **messages[system_index],
                "content": f"{existing}\n\n{note}" if existing else note,
            }
        ctx.note("spotlight.regions", fenced)
    payload["messages"] = messages
    return payload


def _strip_pw_fields(payload: dict[str, Any]) -> dict[str, Any]:
    payload.pop("pw_session_id", None)
    for message in payload.get("messages", []) or []:
        if isinstance(message, dict):
            message.pop("pw_trust", None)
            message.pop("pw_source", None)
    return payload


async def _handle(request: Request, provider_name: str) -> Any:
    settings, pipeline = _state(request)
    provider = get_provider(provider_name)

    payload = await _body(request, settings.max_input_chars * 4)
    session_id = _session_id(request, payload)
    messages = [m.model_dump(exclude_none=True) for m in provider.to_messages(payload)]

    metrics = get_metrics()

    # --- input phase ---------------------------------------------------
    with span("promptwall.input", provider=provider_name) as current:
        ctx = await to_thread.run_sync(
            lambda: pipeline.inspect_request(
                messages, session_id=session_id, tools=payload.get("tools")
            )
        )
        annotate_verdict(current, ctx.verdict)

    bind(request_id=ctx.request_id, session_id=session_id)
    metrics.record_verdict(ctx.verdict)
    request.app.state.audit.record(ctx)

    if ctx.verdict.blocked:
        log.warning(
            "request blocked", extra={"rule": ctx.verdict.reason(), "risk": ctx.verdict.risk}
        )
        return JSONResponse(
            status_code=403,
            content=BlockedResponse.from_verdict(ctx.verdict).model_dump(),
            headers=_decision_headers(ctx.verdict),
        )

    # --- forward -------------------------------------------------------
    upstream_payload = _strip_pw_fields(
        _spotlight_payload(dict(payload), ctx, SpotlightMode(settings.spotlight_mode))
    )
    client = get_client(settings)

    if payload.get("stream"):
        return await _stream(request, provider, client, upstream_payload, ctx, pipeline)

    with span("promptwall.upstream", provider=provider_name):
        response = await client.post_json(
            provider.chat_path, upstream_payload, headers=dict(request.headers)
        )

    return await _guard_response(request, provider, response, ctx, pipeline, metrics)


async def _guard_response(request, provider, response, ctx, pipeline, metrics) -> JSONResponse:
    """Tool phase, then output phase, then hand the response back."""
    settings = request.app.state.settings

    # --- tool phase ----------------------------------------------------
    calls = provider.extract_tool_calls(response)
    if calls:
        tool_calls = [
            ToolCall(name=c.name, arguments=c.arguments, call_id=c.id) for c in calls
        ]
        with span("promptwall.tools", count=len(tool_calls)):
            ctx = await to_thread.run_sync(lambda: pipeline.inspect_tool_calls(ctx, tool_calls))

        # Derive refusals from the findings' own tool metadata. Pairing
        # findings with calls positionally would be wrong: a single call can
        # produce several findings, and the gate short-circuits on the first
        # violation so the lists are not the same length.
        refused = {
            f.meta["tool"]
            for f in ctx.verdict.findings
            if f.rule_id.startswith("tool.") and f.meta.get("tool")
        }
        if refused:
            outcome = "blocked" if settings.enforcing else "would_block"
            if settings.enforcing:
                response = provider.strip_tool_calls(response, refused)
            for _ in refused:
                metrics.record_tool(outcome, "policy")
            log.warning(
                "tool calls refused",
                extra={"tools": sorted(refused), "enforced": settings.enforcing},
            )

    # --- output phase --------------------------------------------------
    text = provider.extract_text(response)
    if text:
        with span("promptwall.output") as current:
            ctx = await to_thread.run_sync(lambda: pipeline.inspect_response(text, ctx=ctx))
            annotate_verdict(current, ctx.verdict)

        if ctx.verdict.blocked:
            metrics.record_verdict(ctx.verdict)
            request.app.state.audit.record(ctx)
            return JSONResponse(
                status_code=403,
                content=BlockedResponse.from_verdict(
                    ctx.verdict, "Response blocked by PromptWall policy."
                ).model_dump(),
                headers=_decision_headers(ctx.verdict),
            )
        if settings.enforcing and ctx.output_text != text:
            response = provider.replace_text(response, ctx.output_text)

    # --- session phase -------------------------------------------------
    if ctx.session_id:
        ctx = await to_thread.run_sync(lambda: pipeline.close_turn(ctx))

    metrics.record_verdict(ctx.verdict)
    request.app.state.audit.record(ctx)
    return JSONResponse(content=response, headers=_decision_headers(ctx.verdict))


async def _stream(request, provider, client, payload, ctx, pipeline) -> StreamingResponse:
    """Proxy a streaming response through the output guard."""
    settings = request.app.state.settings
    engine = pipeline.engine()
    system_prompt = ctx.system_prompt

    def guard(text: str) -> tuple[str, bool, str]:
        """Synchronous guard callback for StreamGuard.

        A trimmed version of L5: redaction plus prompt-leak detection. The
        markdown defang runs here too, since an image beacon in a stream
        leaks exactly as readily as one in a buffered response.
        """
        from ..detectors.sysprompt_leak import detect_leak  # noqa: PLC0415
        from ..detectors.unsafe_markdown import scan_markdown  # noqa: PLC0415

        result = engine.redact(text, output=True)
        guarded = result.text

        if system_prompt:
            leak = detect_leak(guarded, system_prompt)
            if leak.leaked:
                return guarded, True, "response reproduced the system prompt"

        for hit in scan_markdown(guarded):
            if hit.auto_fetch:
                guarded = (
                    guarded[: hit.start]
                    + f"[blocked {hit.kind}: {hit.reason}]"
                    + guarded[hit.end :]
                )
        return guarded, False, ""

    async def body():
        upstream = client.stream(provider.chat_path, payload, headers=dict(request.headers))
        if not settings.enforcing:
            # Monitor mode must not alter the byte stream.
            async for chunk in upstream:
                yield chunk
            return

        stream_guard = StreamGuard(provider, guard)
        async for chunk in stream_guard.process(upstream):
            yield chunk
        if stream_guard.stats.blocked:
            log.warning(
                "stream stopped", extra={"reason": stream_guard.stats.block_reason}
            )

    return StreamingResponse(
        body(),
        media_type="text/event-stream",
        headers={
            **_decision_headers(ctx.verdict),
            "cache-control": "no-cache",
            "x-accel-buffering": "no",
        },
    )


@router.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """OpenAI-compatible chat completions."""
    return await _handle(request, "openai_compat")


@router.post("/v1/messages")
async def anthropic_messages(request: Request):
    """Anthropic Messages API."""
    return await _handle(request, "anthropic")
