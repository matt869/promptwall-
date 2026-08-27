# ADR 001: Layer ordering is fixed, not configurable

**Status:** accepted
**Date:** 2026-08-26

## Context

PromptWall runs seven layers. An obvious feature request is to let operators
reorder or reprioritise them — run the cheap classifier first, skip
normalization for latency, put the tool gate wherever it suits the pipeline.

Ordering here is not a preference. It is a correctness property, and several
of the orderings someone might reasonably choose are silently unsound.

## Decision

**The order in `constants.LAYER_ORDER` is fixed and not runtime-configurable.**

```
L0 normalize -> L1 heuristics -> L2 classifier -> L3 judge
             -> L4 tool gate -> L5 output guard -> L6 conversation
```

Layers may be individually *disabled* — that is what the benchmark's ablation
mode does, and it is how you measure what a layer contributes. They may not
be *reordered*.

## Why each edge exists

**L0 before everything.** Every later layer is only as good as the text it is
given. An attacker who keeps `ignore previous instructions` from *looking*
like that string defeats L1 completely and degrades L2, without engaging with
any detection logic. Homoglyphs, zero-width characters, the Unicode Tag block
and nested base64 all have to be resolved before anything reads the text.

L0 also produces the offset map. Findings are computed in normalized space
but must be reported and redacted against the bytes the caller actually sent,
and nothing downstream can reconstruct that mapping after the fact.

**L1 before L2.** Not for accuracy — for cost and explainability. L1 is
microseconds and produces a rule id an operator can read. Running the
classifier first would spend the budget on traffic a signature would have
settled, and would replace "matched `exf.send_data_to_url`" with "scored
0.91" in the audit log.

**L2 before L3.** L3 costs a model call and hundreds of milliseconds. It runs
only in the uncertainty band between the review and block thresholds, which
cannot be computed until L1 and L2 have both contributed.

**L4 after L1–L3.** The tool gate needs to know whether untrusted content was
steering toward tool use, and that is a finding earlier layers produce.
Gating first would mean deciding authority without the evidence.

**L5 after the model.** It inspects output, so it cannot run earlier. It is
also the only layer that can stop zero-click exfiltration, because an image
URL leaks when the response is *rendered* — detecting the input that caused
it would have had to be perfect.

**L6 last.** It folds this turn's verdict into the session, so it needs the
verdict.

## Consequences

- `LAYER_ORDER` is a single tuple, and the registry will not construct a
  pipeline in any other sequence. Adding a layer means adding it there and to
  `LAYER_CLASSES`, and nowhere else.
- Budget exhaustion degrades in a defined way. Because layers are ordered
  cheapest-and-most-decisive first, running out of time drops the *most
  expensive and least certain* work, which is the right thing to lose.
- Ablation stays meaningful. Disabling L1 measures L1's contribution, rather
  than L1's contribution confounded with a different execution order.

## The cost

An operator whose traffic is dominated by novel attacks might reasonably want
the classifier first, since signatures would mostly waste time. They cannot
have it. We judged that acceptable: the configuration wins a little latency
and loses the audit-log legibility that makes policy tunable at all. If real
deployments show otherwise, the fix is to change the order for everyone after
measuring it — not to add a knob that lets one deployment quietly become
unsound.

## See also

- [ADR 002](002-taint-over-classification.md) — why provenance is primary
- `promptwall/constants.py` — `LAYER_ORDER`
- `promptwall/pipeline/orchestrator.py` — phase execution and budgets
