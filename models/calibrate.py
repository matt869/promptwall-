#!/usr/bin/env python3
"""Pick decision thresholds from data instead of from intuition.

The defaults in `.env.example` (block at 0.90, review at 0.55) are guesses.
They are reasonable guesses, but the right thresholds depend on the traffic a
deployment actually sees, and the cost of the two error types is never equal.

This tool inverts the usual question. Rather than "what recall does threshold
X give", it asks "what is the highest recall available at a false-positive
rate the operator can live with" -- because in practice the FPR budget is the
hard constraint. An operator will accept missing some attacks; they will not
accept breaking one request in twenty.

    python models/calibrate.py --target-fpr 0.01
    python models/calibrate.py --target-fpr 0.01 --model models/artifacts/classifier.onnx
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bench.harness.runner import load_corpus  # noqa: E402
from models.train_classifier import payload_text  # noqa: E402
from promptwall.layers.l2_classifier import (  # noqa: E402
    FallbackScorer,
    OnnxScorer,
    extract_features,
)

ARTIFACTS = ROOT / "models" / "artifacts"


def score_corpus(scorer, records: list[dict]) -> list[tuple[float, int, bool]]:
    """(probability, label, is_hard_negative) for every scoreable record."""
    out = []
    for record in records:
        text = payload_text(record)
        if len(text.strip()) < 12:
            continue
        out.append(
            (
                scorer.score(extract_features(text)),
                int(record.get("label", 0)),
                "hard_negative" in record.get("tags", []),
            )
        )
    return out


def sweep(scored: list[tuple[float, int, bool]], steps: int = 200) -> list[dict]:
    """Metrics across the whole threshold range."""
    rows = []
    for i in range(steps + 1):
        threshold = i / steps
        tp = fp = tn = fn = 0
        hard_fp = hard_total = 0
        for probability, label, hard in scored:
            predicted = probability >= threshold
            if label == 1:
                tp += predicted
                fn += not predicted
            else:
                fp += predicted
                tn += not predicted
                if hard:
                    hard_total += 1
                    hard_fp += predicted
        rows.append(
            {
                "threshold": round(threshold, 4),
                "recall": tp / (tp + fn) if (tp + fn) else 0.0,
                "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
                "precision": tp / (tp + fp) if (tp + fp) else 0.0,
                "hard_fpr": hard_fp / hard_total if hard_total else 0.0,
            }
        )
    return rows


def pick(rows: list[dict], target_fpr: float) -> dict | None:
    """Highest-recall threshold whose FPR stays inside the budget."""
    feasible = [r for r in rows if r["fpr"] <= target_fpr]
    if not feasible:
        return None
    return max(feasible, key=lambda r: (r["recall"], -r["threshold"]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Calibrate L2 decision thresholds.")
    parser.add_argument("--model", default="", help="ONNX model; omit to use the fallback")
    parser.add_argument("--target-fpr", type=float, default=0.01)
    parser.add_argument(
        "--review-fpr",
        type=float,
        default=0.05,
        help="looser budget for the review band, which escalates rather than blocks",
    )
    args = parser.parse_args(argv)

    records = [r for r in load_corpus() if r.get("score", True)]
    if not records:
        print("no corpus; run python scripts/seed_datasets.py", file=sys.stderr)
        return 1

    if args.model:
        path = Path(args.model)
        if not path.is_file():
            print(f"{path} not found", file=sys.stderr)
            return 1
        scorer, label = OnnxScorer(path), path.name
    else:
        scorer, label = FallbackScorer(), "built-in fallback"

    scored = score_corpus(scorer, records)
    attacks = sum(1 for _, y, _ in scored if y == 1)
    print(f"scorer: {label}")
    print(f"corpus: {len(scored)} scoreable records ({attacks} attack)\n")

    rows = sweep(scored)

    print(f"{'threshold':>10} {'recall':>8} {'fpr':>8} {'hard-fpr':>9} {'precision':>10}")
    for row in rows[::10]:
        print(
            f"{row['threshold']:10.2f} {row['recall']:8.3f} {row['fpr']:8.3f} "
            f"{row['hard_fpr']:9.3f} {row['precision']:10.3f}"
        )

    block = pick(rows, args.target_fpr)
    review = pick(rows, args.review_fpr)

    print()
    if block is None:
        print(
            f"No threshold achieves FPR <= {args.target_fpr}. The scorer cannot meet\n"
            "this budget on this corpus; loosen the target or improve the scorer."
        )
        return 1

    print("recommended settings")
    print(f"  PW_THRESHOLD_BLOCK={block['threshold']:.2f}   "
          f"# recall {block['recall']:.3f} at fpr {block['fpr']:.3f}")
    if review:
        print(f"  PW_THRESHOLD_REVIEW={review['threshold']:.2f}  "
              f"# recall {review['recall']:.3f} at fpr {review['fpr']:.3f}")

    print(
        "\nCalibrate on YOUR traffic before trusting these. The shipped corpus is\n"
        "templated and its benign half is not representative of any real\n"
        "application, so a threshold tuned here is a starting point, not a result.\n"
        "Run the gateway in PW_MODE=monitor, then feed audit.log back through\n"
        "bench/harness/runner.py."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
