# Dataset provenance and licensing

## Everything here is generated

Every record under `bench/datasets/` is produced by
[`scripts/seed_datasets.py`](../../scripts/seed_datasets.py) from templates
written for this repository. No third-party dataset is vendored, scraped or
redistributed, so the corpus carries the same licence as the rest of the
project (see [LICENSE](../../LICENSE)) and no attribution obligations
transfer to anyone using it.

That was a deliberate choice with a real cost, and the cost is stated rather
than hidden: **templated attacks are easier than attacks written by people
trying to get through.** Static recall on this corpus is therefore an
optimistic number. `bench/adaptive_attacker.py` exists to measure the part
this corpus cannot, and its results are the ones to quote when the question
is "how good is this really".

## Attack techniques

The techniques the templates instantiate are all publicly documented
prompt-injection research. They are described in general terms in
[`docs/threat-model.md`](../../docs/threat-model.md). Nothing here is novel
offensive capability; the purpose is measurement.

## If you add external datasets

Several public benchmarks are worth running against and none are vendored
here, because their licences differ and some prohibit redistribution. To use
one, place it under `bench/datasets/external/<name>/`, convert it to the
record schema in `manifest.yaml`, and record the following in this file:

| Field | Why |
|---|---|
| Name and URL | so a reader can find the original |
| Licence | so redistribution obligations are explicit |
| Retrieved on | corpora change without notice |
| Conversion notes | any relabelling, filtering or truncation applied |

`bench/datasets/external/` is not tracked, so a clone stays clean.

## Reproducibility

The generator is seeded (`--seed`, default `20260826`) and writes records in
sorted key order, so regenerating produces byte-identical files. A diff in
`bench/datasets/` therefore means the generator changed, which is exactly
when a benchmark result stops being comparable to the one before it.
