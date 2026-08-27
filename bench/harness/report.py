"""Turning benchmark results into something a person can act on.

The report leads with the two numbers that decide whether a defence is
deployable -- recall on attacks and false-positive rate on hard negatives --
and shows confidence intervals next to both, because these corpora are small
enough that a bare point estimate would overstate what was measured.

Per-family breakdowns come next, since an aggregate hides the case that
matters: catching copy-pasted jailbreaks is easy and catching indirect
injection is not.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Importable both as a module and as a script (python bench/harness/report.py).
if __package__:
    from .metrics import Results
else:  # pragma: no cover - script entry point
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from bench.harness.metrics import Results


def _bar(value: float, width: int = 18) -> str:
    filled = round(max(0.0, min(1.0, value)) * width)
    return "#" * filled + "." * (width - filled)


def render_markdown(payload: dict[str, Any]) -> str:
    corpus = payload.get("corpus", {})
    results = payload.get("results", [])
    lines: list[str] = []

    lines.append("# PromptWall benchmark")
    lines.append("")
    lines.append(
        f"Generated {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')} over "
        f"{corpus.get('records', 0)} records "
        f"({corpus.get('attacks', 0)} attack, "
        f"{corpus.get('records', 0) - corpus.get('attacks', 0)} benign)."
    )
    lines.append("")
    lines.append(
        "> These corpora are templated and small. Treat the intervals, not the "
        "point estimates, as the claim. See `docs/benchmark-methodology.md` for "
        "what this does and does not measure."
    )
    lines.append("")

    # --- headline table ---
    lines.append("## Summary")
    lines.append("")
    lines.append(
        "| Defence | Recall | 95% CI | FPR | Hard-neg FPR | F1 | p99 latency |"
    )
    lines.append("|---|---|---|---|---|---|---|")
    for entry in results:
        overall = entry["overall"]
        ci = entry.get("recall_ci95", [0, 0])
        latency = entry.get("latency", {}).get("p99_ms", 0.0)
        lines.append(
            f"| `{entry['defence']}` "
            f"| {overall['recall']:.3f} "
            f"| {ci[0]:.2f}–{ci[1]:.2f} "
            f"| {overall['fpr']:.3f} "
            f"| {entry.get('hard_negative_fpr', 0):.3f} "
            f"| {overall['f1']:.3f} "
            f"| {latency:.2f} ms |"
        )
    lines.append("")

    # --- per family ---
    lines.append("## Recall by attack family")
    lines.append("")
    families: set[str] = set()
    for entry in results:
        families.update(entry.get("by_family", {}))
    families.discard("none")

    header = "| Family | " + " | ".join(f"`{e['defence']}`" for e in results) + " |"
    lines.append(header)
    lines.append("|---" * (len(results) + 1) + "|")
    for family in sorted(families):
        row = [f"| {family} "]
        for entry in results:
            matrix = entry.get("by_family", {}).get(family)
            row.append(f"| {matrix['recall']:.2f} " if matrix else "| – ")
        lines.append("".join(row) + "|")
    lines.append("")

    # --- what got through ---
    lines.append("## What still gets through")
    lines.append("")
    for entry in results:
        missed = entry.get("missed_ids", [])
        if not missed:
            continue
        lines.append(f"**`{entry['defence']}`** missed {len(missed)} shown:")
        lines.append("")
        lines.append("```")
        lines.append("\n".join(missed[:20]))
        lines.append("```")
        lines.append("")

    # --- false alarms ---
    lines.append("## False alarms")
    lines.append("")
    for entry in results:
        alarms = entry.get("false_alarm_ids", [])
        label = ", ".join(alarms[:20]) if alarms else "none"
        lines.append(f"- `{entry['defence']}`: {label}")
    lines.append("")

    # --- latency ---
    lines.append("## Latency")
    lines.append("")
    lines.append("| Defence | mean | p50 | p95 | p99 | max |")
    lines.append("|---|---|---|---|---|---|")
    for entry in results:
        latency = entry.get("latency", {})
        if not latency:
            continue
        lines.append(
            f"| `{entry['defence']}` | {latency.get('mean_ms', 0):.2f} "
            f"| {latency.get('p50_ms', 0):.2f} | {latency.get('p95_ms', 0):.2f} "
            f"| {latency.get('p99_ms', 0):.2f} | {latency.get('max_ms', 0):.2f} |"
        )
    lines.append("")
    return "\n".join(lines)


def render_console(payload: dict[str, Any]) -> str:
    lines = []
    corpus = payload.get("corpus", {})
    lines.append(
        f"corpus: {corpus.get('records', 0)} records, {corpus.get('attacks', 0)} attacks"
    )
    lines.append("")
    lines.append(f"{'defence':28} {'recall':>7} {'fpr':>7} {'hard-neg':>9}  distribution")
    for entry in payload.get("results", []):
        overall = entry["overall"]
        lines.append(
            f"{entry['defence']:28} {overall['recall']:7.3f} {overall['fpr']:7.3f} "
            f"{entry.get('hard_negative_fpr', 0):9.3f}  {_bar(overall['recall'])}"
        )
    return "\n".join(lines)


def from_results(results: list[Results], corpus_size: int, attacks: int) -> dict[str, Any]:
    return {
        "corpus": {"records": corpus_size, "attacks": attacks},
        "results": [r.to_dict() for r in results],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render a benchmark report.")
    parser.add_argument("results", help="results.json produced by runner.py")
    parser.add_argument("--out", default="", help="write markdown here")
    parser.add_argument("--format", default="markdown", choices=["markdown", "console"])
    args = parser.parse_args(argv)

    payload = json.loads(Path(args.results).read_text(encoding="utf-8"))
    text = (
        render_markdown(payload) if args.format == "markdown" else render_console(payload)
    )
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"wrote {out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
