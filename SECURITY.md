# Security policy

## Status

**PromptWall is alpha software and has not had an independent security
review.** It is built carefully and measured honestly — see
[failure analysis](docs/failure-analysis.md) for what gets through — but do
not treat it as a substitute for the other controls in your system.

It is one layer. Tool permissions, data access controls and output handling
in the calling application all still matter.

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.**

Use GitHub's [private vulnerability
reporting](https://github.com/matt869/promptwall-/security/advisories/new).

Useful reports include:

- what an attacker gains, concretely
- a reproduction — ideally a record in the
  [corpus format](bench/datasets/manifest.yaml)
- the version or commit
- relevant configuration (mode, fail mode, policy changes)

Expect an acknowledgement within a few days and an assessment within two
weeks. If a fix is warranted we will agree a disclosure timeline with you and
credit you unless you prefer otherwise.

## What counts as a vulnerability

**In scope**

- Bypassing the **tool gate** — getting a tool call authorised whose
  authority traces to untrusted content. This is the guarantee; a bypass is
  the most serious class of report.
- Escaping **taint tracking** — making untrusted content be labelled as
  trusted, including forging spotlight sentinels.
- **Output guard bypass** — exfiltrating secrets or PII past L5, especially
  zero-click paths.
- **Gateway compromise** — RCE, SSRF through the proxy, auth bypass, admin
  endpoints reachable without an admin key, secrets in logs or error
  responses.
- **Denial of service** — catastrophic regex backtracking, decode bombs,
  unbounded memory growth.
- **Audit integrity** — altering audit records without breaking the hash
  chain.

**Not vulnerabilities**

These are known, documented properties, not bugs:

- **Evading detection (L1/L2/L3).** Roughly 55% of attacks evade detection
  under our own adaptive attacker. Detection is corroboration, not the
  guarantee ([ADR 002](docs/adr/002-taint-over-classification.md)). A novel
  evasion is a very welcome *corpus contribution* — just not a security
  report.
- **Attacks that need mislabelled provenance.** If an integration labels
  retrieved content as `DEVELOPER`, protection is disabled for that span by
  definition.
- **Anything requiring write access** to policy files, configuration or the
  process.
- **Monitor mode not blocking.** That is what monitor mode is.
- **Multi-turn crescendo attacks.** Known weak at 0.33 recall and documented.
- **Model behaviour** — a model saying something objectionable is the
  provider's content policy, not this proxy's job.

If you are unsure which side a finding falls on, report it privately. We would
rather triage an in-scope-looking non-issue than miss a real one.

## Hardening checklist

Before putting this in a request path that matters:

- [ ] `PW_MODE=enforce` (monitor mode blocks nothing)
- [ ] Provenance labelled at the integration — the highest-value step, and
      silent when wrong
- [ ] `tools.yaml` describes **your** tools; the shipped file is an example
- [ ] `default_effect: deny` retained
- [ ] `PW_ADMIN_API_KEYS` set and distinct from client keys
- [ ] `/admin` not reachable from the internet
- [ ] `PW_AUDIT_HMAC_KEY` set if the audit log is evidence
- [ ] `PW_AUDIT_STORE_CONTENT` left `false` unless you have a retention policy
- [ ] `PW_FAIL_MODE=closed` if the model can take consequential action
      ([ADR 003](docs/adr/003-fail-open-vs-fail-closed.md))
- [ ] Redis sessions or sticky routing behind more than one replica
- [ ] Any trained L2 model validated against the built-in scorer
      (`python models/eval_classifier.py`)

## Handling of sensitive data

By design:

- **Prompt content never reaches the application log.** An LLM gateway sees
  every prompt its users send; its log is a high-value target and a
  data-protection liability.
- **Audit content storage is off by default** and must be enabled
  deliberately.
- **Secrets are fingerprinted, never echoed**, including on `/admin/config`.
- **Client keys are not forwarded upstream.** Clients authenticate to
  PromptWall; PromptWall authenticates to the provider with its own
  credential.
- **Block responses are deliberately thin.** Detailed findings would turn
  every blocked request into an oracle for tuning the next attempt.

## Dependencies

Core runtime is FastAPI, pydantic, httpx, PyYAML, regex and
prometheus-client. `onnxruntime` is optional and only needed for a trained
L2 model; `scikit-learn` and `skl2onnx` are training-only and not installed
in the runtime image.

## Offensive tooling in this repository

`bench/adaptive_attacker.py` mutates attacks to find weaknesses, and
`bench/datasets/` contains attack corpora. Both exist for measurement, both
target only this project's own defence, and the techniques are all publicly
documented prompt-injection research. There is nothing here an adversary does
not already have; the value is that it tells the defender first.
