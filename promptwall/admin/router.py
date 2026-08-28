"""Admin and operations endpoints.

Everything here requires an admin key (enforced in AuthMiddleware), because
collectively these expose the policy, the traffic and the ability to change
enforcement behaviour -- which is to say, everything an attacker would want
before attacking the thing PromptWall is protecting.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from fastapi import APIRouter, Body, Query, Request

from ..exceptions import PolicyValidationError, ValidationError
from ..telemetry.logging import get_logger
from . import replay as replay_mod

log = get_logger("admin")
router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/config")
async def get_config(request: Request) -> dict[str, Any]:
    """Effective configuration, with every secret fingerprinted."""
    return request.app.state.settings.redacted()


@router.get("/policy")
async def get_policy(request: Request) -> dict[str, Any]:
    """Active policy summary and reload status."""
    return request.app.state.pipeline.policy_store.status()


@router.get("/policy/rules")
async def list_rules(
    request: Request,
    kind: str = Query("signatures", pattern="^(signatures|tools|redaction)$"),
) -> dict[str, Any]:
    """The rules currently in force, as loaded rather than as written."""
    bundle = request.app.state.pipeline.policy_store.bundle
    if kind == "signatures":
        return {
            "version": bundle.signatures.version,
            "rules": [s.model_dump(mode="json") for s in bundle.signatures.signatures],
        }
    if kind == "tools":
        return {
            "version": bundle.tools.version,
            "default_effect": bundle.tools.default_effect,
            "rules": [r.model_dump(mode="json") for r in bundle.tools.rules],
        }
    return {
        "version": bundle.redaction.version,
        "rules": [r.model_dump(mode="json") for r in bundle.redaction.rules],
    }


@router.post("/policy/reload")
async def reload_policy(request: Request, force: bool = Query(False)) -> dict[str, Any]:
    """Re-read policy from disk.

    A failed reload leaves the previous bundle in force and reports the error
    rather than raising, so a typo cannot take enforcement offline.
    """
    store = request.app.state.pipeline.policy_store
    changed = store.reload(force=force)
    if store.last_error:
        raise PolicyValidationError(store.last_error)

    request.app.state.pipeline.cache.clear()
    log.info("policy reloaded", extra={"changed": changed, "digest": store.bundle.digest})
    return {"reloaded": changed, **store.status()}


@router.get("/stats")
async def stats(request: Request) -> dict[str, Any]:
    """Pipeline, cache, session and audit counters."""
    return {
        **request.app.state.pipeline.status(),
        "audit": request.app.state.audit.stats(),
    }


@router.get("/summary")
async def summary(
    request: Request, limit: int = Query(200, ge=1, le=2000)
) -> dict[str, Any]:
    """Traffic rolled up for the operator console.

    The console could fetch /admin/audit/recent and count client-side, but
    that ships every record to a browser on every refresh purely to throw
    most of them away. Aggregating here keeps the payload flat as the audit
    log grows, and keeps request content out of the browser entirely.
    """
    path = request.app.state.settings.telemetry.audit_path
    records = list(replay_mod.iter_audit(path, limit=100_000))

    decisions: Counter[str] = Counter()
    families: Counter[str] = Counter()
    rules: Counter[str] = Counter()
    layer_ms: dict[str, list[float]] = {}
    risks: list[float] = []

    for record in records:
        decisions[str(record.get("decision", "unknown"))] += 1
        for family in record.get("families") or []:
            families[str(family)] += 1
        for finding in record.get("findings") or []:
            rules[str(finding.get("rule_id", "?"))] += 1
        for layer in record.get("layers") or []:
            if layer.get("ran"):
                layer_ms.setdefault(str(layer.get("layer")), []).append(
                    float(layer.get("duration_ms") or 0.0)
                )
        risk = record.get("risk")
        if isinstance(risk, int | float):
            risks.append(float(risk))

    # Fixed bucket edges rather than a computed range: a histogram whose axis
    # moves with the data cannot be compared against yesterday's.
    buckets = [0.0, 0.1, 0.25, 0.4, 0.55, 0.7, 0.8, 0.9, 1.01]
    histogram = [0] * (len(buckets) - 1)
    for risk in risks:
        for i in range(len(buckets) - 1):
            if buckets[i] <= risk < buckets[i + 1]:
                histogram[i] += 1
                break

    return {
        "total": len(records),
        "decisions": dict(decisions),
        "families": dict(families.most_common(12)),
        "top_rules": [
            {"rule_id": rule, "hits": hits} for rule, hits in rules.most_common(12)
        ],
        "risk_histogram": {
            "edges": buckets[:-1],
            "counts": histogram,
        },
        "layer_latency_ms": {
            name: round(sum(values) / len(values), 3)
            for name, values in sorted(layer_ms.items())
            if values
        },
        "recent": [
            {
                key: record.get(key)
                for key in (
                    "ts",
                    "request_id",
                    "phase",
                    "decision",
                    "risk",
                    "advisory",
                    "families",
                    "duration_ms",
                )
            }
            | {
                "rules": [
                    str(f.get("rule_id")) for f in (record.get("findings") or [])
                ][:6]
            }
            for record in records[-limit:][::-1]
        ],
    }


@router.post("/replay")
async def replay(
    request: Request,
    # B008 is the correct warning in general, but Body(...) in a default
    # is how FastAPI declares a required JSON body -- it is read by the
    # framework at import time, not evaluated per call.
    body: dict[str, Any] = Body(...),  # noqa: B008
) -> dict[str, Any]:
    """Run a conversation through the pipeline without calling the provider.

    Body: {"messages": [...], "tool_calls": [...], "output": "...",
           "layers": ["l0_normalize", ...]}

    ``layers`` restricts execution to a subset, which is how you measure what
    a single layer contributes rather than assuming it earns its place.
    """
    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        raise ValidationError("replay requires a non-empty 'messages' array")

    layers = body.get("layers")
    if layers is not None:
        unknown = set(layers) - set(replay_mod.ALL_LAYERS)
        if unknown:
            raise ValidationError(f"unknown layers: {sorted(unknown)}")

    return replay_mod.replay_messages(
        request.app.state.pipeline,
        messages,
        tool_calls=body.get("tool_calls"),
        output=body.get("output", ""),
        session_id=body.get("session_id", ""),
        layers=layers,
    )


@router.get("/audit/verify")
async def verify_audit(request: Request) -> dict[str, Any]:
    """Walk the audit hash chain and report the first break, if any."""
    return request.app.state.audit.verify()


@router.get("/audit/recent")
async def recent_audit(
    request: Request, limit: int = Query(50, ge=1, le=500)
) -> dict[str, Any]:
    """Most recent audit records."""
    path = request.app.state.settings.telemetry.audit_path
    records = list(replay_mod.iter_audit(path, limit=100_000))
    return {"count": len(records[-limit:]), "records": records[-limit:]}


@router.get("/sessions/{session_id}")
async def get_session(request: Request, session_id: str) -> dict[str, Any]:
    """Accumulated risk state for one conversation."""
    store = request.app.state.pipeline.session_store
    if store is None:
        raise ValidationError("session tracking is not enabled")
    state = store.get(session_id)
    if state is None:
        return {"session_id": session_id, "found": False}
    return {
        "found": True,
        **state.to_dict(),
        "turns_detail": [t.to_dict() for t in state.recent(20)],
    }


@router.delete("/sessions/{session_id}")
async def delete_session(request: Request, session_id: str) -> dict[str, Any]:
    store = request.app.state.pipeline.session_store
    if store is None:
        raise ValidationError("session tracking is not enabled")
    store.delete(session_id)
    return {"deleted": True, "session_id": session_id}


@router.post("/cache/clear")
async def clear_cache(request: Request) -> dict[str, Any]:
    request.app.state.pipeline.cache.clear()
    return {"cleared": True, **request.app.state.pipeline.cache.stats()}
