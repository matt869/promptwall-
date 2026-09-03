# Deployment

## The short version

```bash
pip install -e .

export PW_API_KEYS=$(python -c "import secrets;print(secrets.token_urlsafe(32))")
export PW_UPSTREAM_PROVIDER=openai_compat
export PW_UPSTREAM_BASE_URL=https://api.openai.com/v1
export PW_UPSTREAM_API_KEY=sk-...
export PW_MODE=monitor          # start here. always.

promptwall check                # validate config and policy
promptwall serve
```

Then change your application's `base_url` to `http://localhost:8080/v1` and
its key to the PromptWall key. Nothing else changes.

## Rolling out

The failure mode to avoid is switching on enforcement, blocking legitimate
traffic on day one, and having the whole thing removed. Four stages.

### 1. Monitor

```bash
PW_MODE=monitor
PW_AUDIT_ENABLED=true
```

Nothing is blocked or modified. Verdicts are computed, marked advisory, and
recorded. Every response carries `x-promptwall-decision`, so you can see what
enforcement *would* have done from the client side.

Run this for at least a week of representative traffic. A weekend is not
representative.

### 2. Read what would have broken

```bash
curl -H "authorization: Bearer $PW_ADMIN_KEY" \
     localhost:8080/admin/audit/recent?limit=200 | jq '.records[] |
     select(.decision != "allow") | {decision, risk, families, findings}'
```

Look at every would-be block. For each, decide: real attack, or your
application doing something legitimate that looks like one?

The second kind is what [policy authoring](policy-authoring.md) is for.
Replay a candidate change before shipping it:

```bash
curl -X POST -H "authorization: Bearer $PW_ADMIN_KEY" \
     localhost:8080/admin/replay \
     -d '{"messages":[...]}'
```

Both of those have a page in front of them, which is usually the faster way
to do this stage: `/dashboard` for where risk is landing relative to the
thresholds and which rules are firing, `/playground` for replaying a
candidate change and seeing which layer reacted. Paste an admin key into the
header — it is kept in that browser and sent only to `/admin`.

The pages themselves are static HTML reachable without a key, because they
carry no data. If you would rather not serve them at all:

```bash
PW_UI_ENABLED=false
```

### 3. Label provenance

The single highest-value change on the application side. PromptWall infers
trust from message roles, but a RAG chain that concatenates retrieved chunks
into one string has destroyed that information before the request is built.

```python
from promptwall_client import trusted, untrusted, tool_result

messages = [
    trusted("You are a support assistant."),
    {"role": "user", "content": question},
    tool_result("web_fetch", page_html),        # UNTRUSTED
    untrusted(chunk, source="rag:handbook.md"), # UNTRUSTED, with a source
]
```

Without this you still get detection. You lose taint tracking and tool
gating, which is most of what PromptWall is for.

### 4. Enforce

```bash
PW_MODE=enforce
```

Watch `promptwall_requests_total{decision="block"}` for the first day. Keep
the monitor-mode audit log to compare against.

## Choosing a fail mode

```bash
PW_FAIL_MODE=open     # default
PW_FAIL_MODE=closed
```

Ask what the model can *do*, not what it can say. An assistant that answers
questions should fail open. An agent that can move money, delete records or
email customers should fail closed. Full reasoning in
[ADR 003](adr/003-fail-open-vs-fail-closed.md).

## Sizing and latency

PromptWall adds roughly 2ms at p99 for the input phase with default settings
— immaterial next to a model call. Two things change that:

**The L3 judge** (`PW_L3_ENABLED=true`) adds a model call, budgeted by
`PW_BUDGET_JUDGE_MS`. It only fires in the uncertainty band, so the *average*
cost depends on how much of your traffic lands there. Measure before enabling.

**Streaming** holds back a 256-character tail so patterns spanning chunk
boundaries are caught. Time-to-first-token rises by roughly the time it takes
the model to produce those characters.

The pipeline is CPU-bound and runs in a worker thread. Size on cores, not
memory; a single instance handles hundreds of requests per second on two
cores.

## Sessions behind more than one replica

The default session store is in-process. Behind several replicas, sessions
bind to whichever instance served them and cross-turn detection degrades
silently.

```bash
pip install "promptwall[redis]"      # the client is an optional dependency
export PW_SESSION_BACKEND=redis
export PW_REDIS_URL=redis://redis:6379/0
```

Or use sticky sessions. Either is fine; doing neither is not.

If the `redis` package is missing, the gateway logs a warning and falls back
to in-process sessions rather than refusing to start. The container image
ships the extra, so this only bites a `pip install promptwall` deployment
that then asks for the Redis backend.

Redis being *unreachable* is handled separately and does not fail requests:
a read error is treated as "no session", so the turn is evaluated on its own
merits and cross-turn analysis is skipped for it. Same reasoning as
[ADR 003](adr/003-fail-open-vs-fail-closed.md).

## Secrets

- `PW_API_KEYS` — what clients send. Rotate by listing several during the
  overlap.
- `PW_UPSTREAM_API_KEY` — the provider credential. This is now the only place
  it lives, which is the point: it stops being distributed to every service
  that wants a model.
- `PW_ADMIN_API_KEYS` — separate from client keys. `/admin` exposes policy,
  traffic and replay.
- `PW_AUDIT_HMAC_KEY` — enables the audit hash chain. Set it if the log is
  evidence.

`/admin/config` fingerprints every secret rather than echoing it.

## Audit logging

Off-by-default content storage is deliberate:

```bash
PW_AUDIT_ENABLED=true
PW_AUDIT_STORE_CONTENT=false   # keep this false unless you have decided otherwise
PW_AUDIT_HMAC_KEY=...
```

A file containing every prompt your users sent is exactly what an attacker
wants and a data-protection liability besides. Turning it on should be a
documented decision with a retention policy attached.

Verify the chain:

```bash
curl -H "authorization: Bearer $PW_ADMIN_KEY" localhost:8080/admin/audit/verify
```

## Health checks

| Endpoint | Use |
|---|---|
| `/healthz` | Liveness. Trivial by design — it must not depend on policy or the provider. |
| `/readyz` | Readiness. 503 when a non-advisory layer is unavailable, so an orchestrator pulls the instance instead of routing through a gateway that is not inspecting properly. |
| `/metrics` | Prometheus. |

`/readyz` also reports which L2 scorer is live, so a degraded classifier
cannot be in force without anyone knowing.

## Docker

```bash
docker compose up
```

Runs the gateway with the echo provider by default, so it starts with no
credentials. Set `PW_UPSTREAM_*` for a real provider. Redis is wired up from
the start, because in-process sessions degrade silently behind more than one
replica.

Add the observability profile for Prometheus and a pre-provisioned Grafana
dashboard on `:3000`:

```bash
docker compose --profile observability up
```

## Kubernetes

```bash
kubectl create secret generic promptwall   --from-literal=api-keys="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"   --from-literal=admin-api-keys="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"   --from-literal=upstream-api-key=sk-...

kubectl apply -k .
```

The kustomization lives at the repository root so it can generate the policy
ConfigMap from the real rule files rather than a second copy that would
drift. The generated name is content-hashed, so **editing a rule rolls the
Deployment automatically** — no checksum annotation to remember, and no
policy change that silently fails to take effect.

Secrets are deliberately not generated by kustomize, so credentials never
enter the repository.

## Policy updates without a restart

```bash
curl -X POST -H "authorization: Bearer $PW_ADMIN_KEY" \
     localhost:8080/admin/policy/reload
```

Atomic: a malformed file leaves the previous policy in force and returns the
error. The verdict cache is keyed by policy digest, so a reload invalidates
it automatically.

## Common mistakes

**Staying in monitor mode.** It is the right way to start and the wrong way
to stay. Nothing is blocked.

**Not labelling provenance.** Detection still works; the guarantee does not.

**Trusting the shipped tool policy.** `tools.yaml` describes *example* tools.
Yours are different. `default_effect: deny` means an unlisted tool is refused,
which is the safe failure, but it means nothing until your tools are listed.

**Training a classifier and shipping it unevaluated.** On a small corpus a
trained model learns artifacts and can be worse than the built-in scorer.
Check with `python models/eval_classifier.py` — the gateway logs a warning
when a trained model is active.

**Exposing `/admin` publicly.** It requires an admin key, but it should not
be reachable from the internet regardless.

## See also

- [architecture.md](architecture.md)
- [policy-authoring.md](policy-authoring.md)
- [ADR 003](adr/003-fail-open-vs-fail-closed.md)
