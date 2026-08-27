# Architecture

How a request moves through PromptWall, and why the pieces are arranged this
way.

## Request path

```
   client
     │  POST /v1/chat/completions
     ▼
  ┌─────────────────────────────────────────────────┐
  │ RequestID -> Auth -> RateLimit                  │  middleware
  └─────────────────────────────────────────────────┘
     │
     ▼
  ┌─────────────────────────────────────────────────┐
  │ taint.tracker: label every message               │
  │   system/developer -> DEVELOPER                  │
  │   user             -> USER                       │
  │   assistant        -> THIRD_PARTY                │
  │   tool/function    -> UNTRUSTED                  │
  └─────────────────────────────────────────────────┘
     │
     ▼  INPUT phase (budget: 120ms)
  ┌─────────────────────────────────────────────────┐
  │ L0 normalize   NFKC, invisibles, confusables,    │
  │                nested decoding, offset map       │
  │ L1 heuristics  signatures, trust-scoped          │
  │ L2 classifier  score untrusted spans             │
  │ L3 judge       only in the uncertainty band      │
  └─────────────────────────────────────────────────┘
     │
     ├── blocked? ──▶ 403, provider never called
     │
     ▼
  ┌─────────────────────────────────────────────────┐
  │ spotlight: fence untrusted spans as data         │
  └─────────────────────────────────────────────────┘
     │
     ▼
   model provider
     │
     ▼  TOOL phase
  ┌─────────────────────────────────────────────────┐
  │ L4 tool gate   authority, not content            │
  └─────────────────────────────────────────────────┘
     │
     ▼  OUTPUT phase (budget: 80ms)
  ┌─────────────────────────────────────────────────┐
  │ L5 output guard  redact, defang, leak detection  │
  └─────────────────────────────────────────────────┘
     │
     ▼  SESSION phase
  ┌─────────────────────────────────────────────────┐
  │ L6 conversation  crescendo, persistent probing   │
  └─────────────────────────────────────────────────┘
     │
     ▼
   client (+ x-promptwall-decision, -risk, -request-id)
```

## The load-bearing idea

Everything rests on one data structure. `TaintMap` partitions a string into
spans, each labelled with where it came from:

```python
TaintMap.uniform(len(text), TrustLevel.USER, "user")
         .with_span(Span(120, 400, TrustLevel.UNTRUSTED, "tool:web_fetch"))
```

Three properties matter:

**It is total.** Every offset is labelled. There is no "unknown" — unlabelled
text is the most dangerous thing that could exist in a system like this, so
it cannot exist. Gaps fill with the map's default, which is `UNTRUSTED`.

**Windows resolve downward.** `min_trust(start, end)` over a span crossing a
boundary returns the *lower* level. The attacker chooses where their content
ends, so resolving optimistically would be directly exploitable.

**It survives rewriting.** L0 changes the text; `OffsetMap` carries the
labels across, and `span_to_original` widens outward when the mapping is
approximate — redacting one character too many, never one too few.

See [ADR 002](adr/002-taint-over-classification.md) for why this is primary
and classification is corroboration.

## Layers

Each layer implements one method and must not raise. Layers *report*; the
orchestrator *decides*. That split keeps thresholds in one place and is what
makes benchmark ablation meaningful.

| Layer | Phase | Cost | Job |
|---|---|---|---|
| L0 normalize | input | ~2ms | Unmask. NFKC, strip invisibles, fold confusables, decode nested payloads, build the offset map. |
| L1 heuristics | input | ~4ms | Match signatures against raw, normalized and decoded text, gated by provenance. |
| L2 classifier | input | ~8ms | Score untrusted spans as instruction-like. ONNX model or built-in weights. |
| L3 judge | input | ~900ms | LLM-as-judge, only between the review and block thresholds. Advisory. |
| L4 tool gate | tool | ~2ms | Authorize tool calls on provenance. **The guarantee.** |
| L5 output guard | output | ~5ms | Redact secrets and PII, defang auto-fetching markup, detect prompt recitation. |
| L6 conversation | session | ~1ms | Crescendo and persistent-probing detection across turns. |

Order is fixed and not configurable — see [ADR 001](adr/001-layer-ordering.md).

## Spotlighting

Before untrusted spans reach the model they are re-encoded as unmistakable
data:

```
<<<pw:untrusted-data id="0" src="tool:web_fetch" enc="datamark">>>
Revenue▁rose▁12%▁in▁EMEA▁this▁quarter.
pw:end-untrusted-data>>>
```

Three modes: `delimit` fences the span, `datamark` additionally replaces
spaces with a marker glyph so the boundary is present in *every* token rather
than only at the edges, and `encode` base64s it.

The non-negotiable part is scrubbing forged sentinels from the content first.
Wrapping attacker content in a fence the attacker can close is worse than not
fencing at all, because it manufactures the appearance of trust.

Spotlighting is a request to the model, and a sufficiently persuasive
injection is a competing request. It is defence in depth behind L4, never
instead of it.

## Risk aggregation

Findings combine by noisy-OR:

```
risk = 1 - Π(1 - weight_i)
```

Summing lets a pile of low-severity noise outrank one critical hit. Taking
the max discards the corroborating evidence that separates a real attack from
an unlucky phrase. Noisy-OR saturates toward 1 while letting independent weak
signals reinforce each other.

Decisions only ratchet upward. A later layer cannot overturn an earlier
block, or the outcome would depend on layer ordering in a way an attacker
could steer.

Mitigated findings carry zero or reduced weight: once a secret has been
redacted the response is safe, and blocking it anyway would turn the output
guard into a denial-of-service vector.

## Budgets

Each phase has a wall-clock budget. Layers are ordered cheapest-and-most-
decisive first, so exhaustion drops the most expensive and least certain
work. A gateway that adds unpredictable latency gets removed from the request
path, which makes the budget a security control rather than a performance
nicety.

L3 declares `separate_budget` because its cost exceeds the whole input budget
by design; it is governed by its own timeout instead.

## Policy

Three YAML packs — signatures, tools, redaction — loaded all-or-nothing and
identified by a sha256 digest recorded on every verdict. `PolicyStore` swaps
an immutable bundle under a lock, so reloads are atomic and a typo leaves the
previous policy in force rather than taking enforcement offline.

See [policy-authoring.md](policy-authoring.md).

## Concurrency

The pipeline is synchronous and CPU-bound; the proxy is async. Requests run
the pipeline in a worker thread via `anyio.to_thread.run_sync`, so regex and
feature extraction never stall the event loop. There is one concurrency model
at the edge and one inside, and they do not mix.

## Failure behaviour

Fail open by default, fail closed by configuration, never silently either way
— see [ADR 003](adr/003-fail-open-vs-fail-closed.md).

## See also

- [threat-model.md](threat-model.md) — what this defends against
- [deployment.md](deployment.md) — running it
- [benchmark-methodology.md](benchmark-methodology.md) — how well it works
