"""Replaying traffic through the pipeline without forwarding it.

The tool operators actually need. Tuning a security policy means answering
"would this change have blocked yesterday's false positive, and would it
still catch the attack?" -- and the only honest way to answer that is to run
the real pipeline over real traffic.

Replay never calls the provider. It is safe to point at production audit
records, and it is the mechanism behind the benchmark's ablation runs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from ..constants import LayerName
from ..pipeline.context import ToolCall


def replay_messages(
    pipeline,
    messages: list[dict[str, Any]],
    *,
    tool_calls: list[dict[str, Any]] | None = None,
    output: str = "",
    session_id: str = "",
    layers: list[str] | None = None,
) -> dict[str, Any]:
    """Run one conversation through the pipeline and return the full trace.

    ``layers`` restricts execution to a subset, which is how ablation works:
    disabling L4 and re-running the attack corpus measures what the tool gate
    is actually contributing, rather than assuming.
    """
    if layers is not None:
        _apply_ablation(pipeline, layers)

    try:
        ctx = pipeline.inspect_request(messages, session_id=session_id)

        if tool_calls:
            ctx = pipeline.inspect_tool_calls(
                ctx,
                [
                    ToolCall(
                        name=str(call.get("name", "")),
                        arguments=call.get("arguments") or {},
                        call_id=str(call.get("id", "")),
                    )
                    for call in tool_calls
                ],
            )
        if output:
            ctx = pipeline.inspect_response(output, ctx=ctx)
        if session_id:
            ctx = pipeline.close_turn(ctx)

        return {
            "verdict": ctx.verdict.to_audit_dict(include_content=False),
            "context": ctx.to_debug_dict(),
            "output": ctx.output_text,
            "normalized_preview": ctx.normalized[:2000],
            "decoded": [
                {"scheme": d.scheme, "depth": d.depth, "text": d.text[:200]}
                for d in ctx.decoded
            ],
            "scratch": {k: str(v)[:300] for k, v in ctx.scratch.items()},
        }
    finally:
        if layers is not None:
            _restore(pipeline)


def _apply_ablation(pipeline, keep: list[str]) -> None:
    """Temporarily disable layers not in ``keep``."""
    wanted = {str(name).lower() for name in keep}
    saved: dict[str, bool] = {}
    for layer in pipeline.registry.all():
        saved[str(layer.name)] = layer.enabled
        if str(layer.name).lower() not in wanted:
            layer.disable("ablated for replay")
    pipeline._ablation_saved = saved  # noqa: SLF001 - private by intent


def _restore(pipeline) -> None:
    saved = getattr(pipeline, "_ablation_saved", None)
    if not saved:
        return
    for layer in pipeline.registry.all():
        if saved.get(str(layer.name)):
            layer._enabled = True  # noqa: SLF001
    del pipeline._ablation_saved


def iter_audit(path: str | Path, limit: int = 1000) -> Iterator[dict[str, Any]]:
    """Stream audit records, newest last. Malformed lines are skipped."""
    file = Path(path)
    if not file.is_file():
        return
    count = 0
    with file.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
            count += 1
            if count >= limit:
                return


def find_record(path: str | Path, request_id: str) -> dict[str, Any] | None:
    for record in iter_audit(path, limit=100_000):
        if record.get("request_id") == request_id:
            return record
    return None


def diff_verdicts(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Compare two replays. What a policy change actually did."""
    rules_before = {f["rule_id"] for f in before.get("findings", [])}
    rules_after = {f["rule_id"] for f in after.get("findings", [])}
    return {
        "decision": {
            "before": before.get("decision"),
            "after": after.get("decision"),
            "changed": before.get("decision") != after.get("decision"),
        },
        "risk": {
            "before": before.get("risk"),
            "after": after.get("risk"),
            "delta": round((after.get("risk") or 0) - (before.get("risk") or 0), 6),
        },
        "rules_added": sorted(rules_after - rules_before),
        "rules_removed": sorted(rules_before - rules_after),
    }


ALL_LAYERS = [str(name) for name in LayerName]
