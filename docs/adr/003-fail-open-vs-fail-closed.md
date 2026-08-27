# ADR 003: Fail open by default, fail closed by choice

**Status:** accepted
**Date:** 2026-08-26

## Context

A layer will eventually fail: a model artifact goes missing, the judge's
provider times out, a policy regex hits its evaluation ceiling, something
raises that we did not anticipate.

Two options, and the security-purist answer is not obviously right.

**Fail closed** — refuse the request. Nothing gets through unexamined, and an
attacker who can induce a failure gets nothing.

**Fail open** — forward it, and record the gap. The application keeps
working, and an attacker who can induce a failure gets an unprotected
request.

The purist argument has a practical problem. PromptWall sits in the request
path of a live application. A gateway that converts a partial internal fault
into a total outage gets removed from the request path, and a defence that is
not deployed has a recall of zero. The realistic comparison is not *fail-open
vs fail-closed*; it is *fail-open vs not deployed*.

## Decision

**Default to fail open. Make fail closed one environment variable. Never let
either mode silently weaken the guarantee.**

```bash
PW_FAIL_MODE=open     # default: degrade and record
PW_FAIL_MODE=closed   # refuse when a layer cannot run
```

Three rules make the default defensible.

**1. Advisory layers never fail a request, in either mode.** A layer is
advisory when its absence does not weaken the core guarantee. L3 is the only
one: the judge being unreachable costs detection quality, but taint tracking
and the tool gate are untouched. Failing requests closed over an advisory
layer trades a real outage for a hypothetical attack.

**2. A failure is always recorded.** Every failed layer produces a
`LayerReport` carrying the error, lands in the audit log, and increments a
metric. Fail-open means *degrade visibly*, never *degrade silently*.

**3. The parts that cannot fail, do not.** Taint tracking is pure computation
over data already in the request — no model, no network, no I/O. The tool
gate is a comparison against policy already in memory. Neither has a failure
mode that fail-open could paper over. What degrades under fail-open is
*detection*; what does not degrade is *authority*.

Point 3 is what makes this defensible rather than a shortcut. The layers that
can break are the probabilistic ones, and the guarantee does not rest on them
([ADR 002](002-taint-over-classification.md)).

## Consequences

**Fail open (default)**

- A judge outage degrades detection quality; L0–L2 and L4–L6 continue.
- A missing classifier artifact falls back to the built-in scorer.
- A malformed policy reload leaves the previous policy in force.
- `/readyz` returns 503 when a non-advisory layer is down, so an orchestrator
  pulls the instance from rotation rather than routing through a gateway that
  is not inspecting properly.

**Fail closed**

- Any non-advisory layer failure blocks the request.
- Appropriate where the model can take consequential action and the
  application can tolerate refusals: financial operations, destructive tools,
  regulated environments.
- Requires capacity planning for the failure case. If the judge times out
  under load and you are failing closed, a slow provider becomes an outage.

## When to choose fail closed

Ask what the model can *do*, not what it can say.

An assistant that answers questions should fail open: an unexamined answer is
a small risk, and an outage is a certain one. An agent that can move money,
delete records or email customers should fail closed, because the cost of one
unexamined request exceeds the cost of a refusal.

## Alternatives considered

**Fail closed by default.** Rejected: it makes the first production incident
a PromptWall outage, and the fix operators reach for is removal.

**Per-layer fail modes.** Rejected as configuration surface that mostly
produces incoherent combinations. The advisory flag already captures the one
distinction that carries real meaning.

**Timeout-and-continue with no signal.** Rejected. That is fail-open with the
evidence deleted, which is how a defence quietly stops working for months.

## See also

- `promptwall/pipeline/orchestrator.py` — `_handle_failure`
- `promptwall/config.py` — `FailMode`
- [deployment guide](../deployment.md) — choosing a mode
