# Changelog

Notable changes to PromptWall. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow
[semver](https://semver.org/).

## [Unreleased]

## [0.1.0] — 2026-08-26

First release. Alpha: interfaces are still moving and there has been no
independent security review.

### Core

- **Taint tracking** (`promptwall/taint/`) — a total, gap-free partition of
  every request into trust-labelled spans. Windows straddling a boundary
  resolve to the *lower* trust, since the attacker chooses where their span
  ends. Labels survive rewriting via an offset map that widens outward on
  ambiguity, so redaction errs toward covering one character too many.
- **Spotlighting** — delimiting, datamarking and base64 modes, with forged
  sentinels scrubbed from untrusted content first.
- **Seven defence layers** (L0–L6) in a fixed order, each independently
  ablatable for measurement.
- **Policy engine** — three reviewable YAML packs loaded all-or-nothing,
  identified by a content digest recorded on every verdict, hot-reloadable
  without dropping traffic.
- **Tool gate** — authorization on provenance rather than content. The layer
  the guarantee rests on.

### Gateway

- OpenAI-compatible and Anthropic endpoints; an `echo` provider for running
  with no credentials.
- Streaming output guard that withholds a tail so patterns spanning chunk
  boundaries are caught.
- Monitor and enforce modes; fail-open default with fail-closed available.
- API key auth with constant-time comparison, per-principal rate limiting,
  request correlation.
- Prometheus metrics, structured logs that never carry prompt content, and a
  hash-chained audit log.
- Admin API: policy inspection and reload, session state, audit verification,
  and replay with layer ablation.

### Measurement

- 150-record templated corpus with a hard-negative split.
- Harness reporting recall, hard-negative FPR separately, per-family
  breakdowns, Wilson intervals and p99 latency.
- Baselines: `no_defense`, `regex_only`, `rebuff_like`. `llama_guard` reports
  itself unavailable rather than substituting a guess.
- Adaptive attacker measuring evasion under mutation.
- `scripts/bench_delta.py` as a CI regression gate.

Results: recall 0.924 (CI 0.86–0.96), FPR 0.029, hard-negative FPR 0.067,
p99 1.96ms. Under adaptive mutation roughly 55% of attacks evade *detection*;
the tool gate is unaffected.

### Also

- Python SDK with provenance helpers and a LangChain retriever wrapper.
- Vulnerable-app demo: 2 exfiltrations without PromptWall, 0 with.
- L2 training pipeline. On the shipped corpus the built-in scorer beats the
  trained model on held-out data, and `models/eval_classifier.py` says so.
- 133 tests; ADRs for the three load-bearing decisions.

### Known limitations

- Multi-turn crescendo recall is 0.33 — the weakest area.
- Detection is evadable under adaptation, by design.
- Mislabelled provenance disables protection for that span, silently.
- In-process sessions degrade across replicas without Redis or sticky
  routing.

See [failure analysis](docs/failure-analysis.md).

[Unreleased]: https://github.com/matt869/promptwall-/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/matt869/promptwall-/releases/tag/v0.1.0
