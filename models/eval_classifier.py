#!/usr/bin/env python3
"""Evaluate the L2 classifier, and check it actually beats the fallback.

The comparison that matters is not "is the trained model good" but "is it
better than the free thing already in the box". A trained model that loses to
twenty hand-set weights is not worth the artifact, the load time, or the
supply-chain surface -- and on a small templated corpus that is a live
possibility, because the model learns template quirks rather than signal.

This script reports both and says which won, so the answer is measured
instead of assumed.

    python models/eval_classifier.py
    python models/eval_classifier.py --model models/artifacts/classifier.onnx
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bench.harness.metrics import Confusion, percentile, wilson_interval
from bench.harness.runner import load_corpus
from models.train_classifier import payload_text, split_by_family
from promptwall.layers.l2_classifier import (
    FallbackScorer,
    OnnxScorer,
    extract_features,
)

ARTIFACTS = ROOT / "models" / "artifacts"


def evaluate(scorer, records: list[dict], threshold: float) -> dict:
    matrix = Confusion()
    scores: list[float] = []
    hard_matrix = Confusion()

    for record in records:
        text = payload_text(record)
        if len(text.strip()) < 12:
            continue
        probability = scorer.score(extract_features(text))
        scores.append(probability)
        predicted = int(probability >= threshold)
        label = int(record.get("label", 0))

        outcome = type("O", (), {"label": label, "predicted": predicted})()
        matrix.add(outcome)
        if "hard_negative" in record.get("tags", []):
            hard_matrix.add(outcome)

    return {
        "matrix": matrix,
        "hard": hard_matrix,
        "mean_attack": 0.0,
        "scores": scores,
    }


def _auc(scorer, records: list[dict]) -> float:
    """Rank-based AUC, so the score is threshold-independent."""
    pairs = []
    for record in records:
        text = payload_text(record)
        if len(text.strip()) < 12:
            continue
        pairs.append((scorer.score(extract_features(text)), int(record.get("label", 0))))
    positives = [s for s, y in pairs if y == 1]
    negatives = [s for s, y in pairs if y == 0]
    if not positives or not negatives:
        return 0.0
    wins = sum(
        1.0 if p > n else 0.5 if p == n else 0.0 for p in positives for n in negatives
    )
    return wins / (len(positives) * len(negatives))


def report(name: str, result: dict, auc: float, threshold: float) -> None:
    matrix, hard = result["matrix"], result["hard"]
    lo, hi = wilson_interval(matrix.tp, matrix.tp + matrix.fn)
    print(f"\n{name}")
    print(f"  AUC            {auc:.4f}")
    print(f"  recall         {matrix.recall:.3f}  (95% CI {lo:.2f}-{hi:.2f})")
    print(f"  precision      {matrix.precision:.3f}")
    print(f"  fpr            {matrix.fpr:.3f}")
    print(f"  hard-neg fpr   {hard.fpr:.3f}   ({hard.fp}/{hard.fp + hard.tn})")
    scores = result["scores"]
    if scores:
        print(
            f"  score spread   p50={percentile(scores, 50):.2f} "
            f"p90={percentile(scores, 90):.2f} max={max(scores):.2f}"
        )
    print(f"  at threshold   {threshold}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate and compare L2 scorers.")
    parser.add_argument("--model", default=str(ARTIFACTS / "classifier.onnx"))
    parser.add_argument("--threshold", type=float, default=0.55)
    parser.add_argument("--holdout", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=20260826)
    parser.add_argument(
        "--all",
        action="store_true",
        help="evaluate on the WHOLE corpus, including data the model trained on",
    )
    args = parser.parse_args(argv)

    corpus = [r for r in load_corpus() if r.get("score", True)]
    if not corpus:
        print("no corpus; run python scripts/seed_datasets.py", file=sys.stderr)
        return 1

    # Evaluate on held-out data by default. Scoring a trained model on records
    # it was fitted to reports memorisation as if it were generalisation, and
    # here it also makes the comparison unfair: the fallback has no training
    # set, so any leakage is a pure handicap against it. The split mirrors
    # train_classifier.py exactly (same function, same seed).
    if args.all:
        records = corpus
        print(
            "WARNING: --all evaluates on the training data too. "
            "The trained model's numbers are inflated; the fallback's are not."
        )
    else:
        _, records, held = split_by_family(corpus, args.holdout, args.seed)
        print(
            f"held-out evaluation: {len(records)} records, "
            f"unseen attack families: {', '.join(held)}"
        )

    fallback = FallbackScorer()
    fallback_result = evaluate(fallback, records, args.threshold)
    fallback_auc = _auc(fallback, records)
    report("built-in fallback (hand-set weights)", fallback_result, fallback_auc, args.threshold)

    model_path = Path(args.model)
    if not model_path.is_file():
        print(f"\nno trained model at {model_path}; nothing to compare against.")
        print("Train one with: python models/train_classifier.py && python models/export_onnx.py")
        return 0

    try:
        onnx = OnnxScorer(model_path)
    except Exception as exc:
        print(f"\ncould not load {model_path}: {exc}", file=sys.stderr)
        return 1

    onnx_result = evaluate(onnx, records, args.threshold)
    onnx_auc = _auc(onnx, records)
    report(f"trained model ({model_path.name})", onnx_result, onnx_auc, args.threshold)

    print("\n" + "=" * 62)
    delta = onnx_auc - fallback_auc
    if delta > 0.02:
        print(f"VERDICT: the trained model wins by {delta:+.4f} AUC. Ship it.")
    elif delta < -0.02:
        print(f"VERDICT: the fallback wins by {-delta:.4f} AUC.")
        print(
            "This is the expected outcome on a small templated corpus: the model\n"
            "learns template artifacts rather than signal. Do not ship the artifact\n"
            "on this evidence -- train on your own traffic, where the phrasing is\n"
            "real and the benign class is representative."
        )
    else:
        print(f"VERDICT: indistinguishable ({delta:+.4f} AUC).")
        print("Prefer the fallback: no artifact to ship, load, version or trust.")
    print("=" * 62)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
