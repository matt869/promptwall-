# Changelog

Notable changes to PromptWall. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow
[semver](https://semver.org/).

## [Unreleased]

### Added

- **Operator console** at `/dashboard` and `/playground`, served as static
  HTML with no build step and no third-party assets. The pages carry no data:
  every number is fetched from `/admin` at runtime and still requires an
  admin key, so the shells are public without widening disclosure. Off with
  `PW_UI_ENABLED=false`.
- `GET /admin/summary` — decisions, families, top rules, a fixed-edge risk
  histogram, per-layer latency and a newest-first feed, rolled up from the
  audit log in one pass so the console does not ship every record to a
  browser on each refresh.
- Seven signatures: `leak.own_delimiters`, `leak.quote_verbatim`,
  `exf.recipient_address`, `exf.cloud_metadata`, `tool.secret_file_read`,
  `tool.path_traversal`, `tool.destructive_sql`. The three `tool.*` rules
  deliberately do not scope to untrusted provenance, because they key on a
  dangerous *object* — a private key path, a traversal sequence, a metadata
  address — rather than on an invocation.
- `Signature.quotable` (policy field, default true). L1's quoted-context
  discount now skips rules that opt out. Backticks around `cat ~/.ssh/id_rsa`
  are how the payload is delivered, not evidence it is being discussed, and
  the discount was cutting such a hit to a third of its weight.
- Benign multi-turn sessions in the corpus (`benign/sessions/`). The
  multiturn split was previously all attacks, which made every cross-turn
  threshold unfalsifiable. Two of the four open exactly the way the crescendo
  ladders do.
- Eight hard negatives, each of which matched a draft of a rule added here.

### Changed

- `io.ignore_previous` no longer fires on the bare "disregard the above"
  form unless it ends the clause. It was matching "please disregard the above
  draft and use the second one instead" — an ordinary editing request, and
  the corpus's only false positive.
- Crescendo EWMA gate 0.25 → 0.10 (`CRESCENDO_MIN_EWMA`, now named). The old
  value sat above where the quietest ladders run, which ruled out the case
  the detector exists for. Measured against the new benign sessions: ordinary
  conversations reach at most 0.04 and trend flat or down; the ladders run
  0.12–0.47 while trending up.
- `l6.prior_attempts` weighs a repeat of a family the session has already
  tried (0.45) above an unrelated earlier attempt (0.15).
- Findings always record which rendering matched. `target` was only set when
  a rule matched more than once, which left L1's cross-rendering
  corroboration check reading a field that was usually absent.

- The dashboard names the two states an operator should not have to hunt
  for: **monitor mode**, where every number on the page looks like
  enforcement and none of it is, and **degraded**, naming the unavailable
  layers.

### Fixed

- `l6.prior_attempts` reported a "repeat" the first time a family ever
  appeared, because the sticky-flag set was compared *after* the current
  turn had been folded into it. It now compares against the flags held
  before the turn.
- `/admin/summary` re-read the entire audit log on every request, from the
  event loop. At 100k records that is ~24 MB and ~900 ms, polled every five
  seconds by an open dashboard — so the console would repeatedly stall the
  gateway it was monitoring for seven times its own input latency budget.
  It is now incremental (`promptwall/admin/summary.py`), holding counters
  between calls and folding only newly appended bytes, and served off the
  event loop. An idle poll went 964 ms → 0.35 ms. Torn writes and log
  rotation are handled explicitly rather than by luck.
- `/admin/audit/recent` had the same defect and now seeks backward from the
  end of the file (`replay.tail_audit`). It was parsing 100k records into
  memory to return the last fifty: ~1.6 s of blocked event loop per call,
  against 0.6 ms for the tail read, for byte-identical output.
- The dashboard treated `/readyz`'s 503 as a failure and blanked itself when
  the gateway was degraded — which is the moment the layer detail in that
  response is most wanted. It now reads through the 503 and reports what is
  unavailable.
- Dashboard polls no longer overlap. The refresh timer fired on a schedule
  regardless of whether the previous load had finished, so a cold summariser
  or a slow link could stack requests that then rendered over each other.
- A missing admin key in the playground rendered as a red error on first
  load, reporting the console as broken when it was working as designed.

Results on the expanded 174-record corpus: recall 0.991 (CI 0.95–1.00), FPR
0.000, hard-negative FPR 0.000, p99 3.20 ms. Under adaptive mutation roughly
51% of attacks evade *detection*, down from 58%; the tool gate is unaffected
either way. One corpus attack is undetected by design — see the README.

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
- Redis session store (`promptwall[redis]`), required behind more than one
  replica. Serialised state is versioned, and an unreachable Redis degrades
  to "no session" rather than failing requests.
- Container image, compose stack with Prometheus and a provisioned Grafana
  dashboard, and Kubernetes manifests applied with `kubectl apply -k .`. The
  policy ConfigMap is generated from the real rule files and content-hashed,
  so editing a rule rolls the Deployment automatically.
- 149 tests; ADRs for the three load-bearing decisions. `ruff` and `mypy`
  both clean.

### Known limitations

- Multi-turn crescendo recall is 0.33 — the weakest area.
- Detection is evadable under adaptation, by design.
- Mislabelled provenance disables protection for that span, silently.
- In-process sessions degrade across replicas without Redis or sticky
  routing.

See [failure analysis](docs/failure-analysis.md).

### Fixed before release

Found by auditing the shipped configuration against the code, and by running
`mypy` for the first time:

- `PW_SESSION_BACKEND=redis` was selected by both the compose stack and the
  Kubernetes manifests, but `redis_store.py` did not exist. Every shipped
  deployment config silently fell back to in-process sessions -- exactly the
  failure the docs warn about.
- The Kubernetes manifests referenced a `promptwall-policy` ConfigMap and a
  `promptwall-redis` Service that were never defined. Valid YAML, dangling
  references, pods stuck in `ContainerCreating`.
- The compose stack mounted Grafana dashboards without a provider or a
  datasource, so the dashboard silently loaded nothing.
- `Finding.weight` was typed `float | None`, which leaked `None` into every
  arithmetic site touching a weight. Replaced with a negative sentinel, since
  real weights are 0..1.
- The ONNX probability extractor defaulted a missing class key to `0.0`,
  which reads as "definitely benign" -- a security layer failing open with no
  signal. It now returns `None` and ultimately raises.

CI now renders the Kubernetes manifests and checks that every reference
resolves, because these are the failures that only appear at deploy time.

[Unreleased]: https://github.com/matt869/promptwall-/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/matt869/promptwall-/releases/tag/v0.1.0
