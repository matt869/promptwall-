#!/usr/bin/env python3
"""Train the L2 classifier.

Uses exactly the feature extractor the gateway uses at serving time
(`promptwall.layers.l2_classifier.extract_features`). That is not a
convenience -- training-serving skew is the classic way a deployed model
quietly stops meaning what its evaluation said, and sharing one function
makes it impossible here.

Logistic regression, deliberately. The features are interpretable, so the
learned weights can be read and argued with, and a security control whose
decisions nobody can explain is one nobody can tune. A gradient-boosted model
would score a little better on this corpus and be considerably harder to
trust.

    python models/train_classifier.py --out models/artifacts/classifier.pkl
    python models/export_onnx.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bench.harness.runner import load_corpus  # noqa: E402
from promptwall.layers.l2_classifier import FEATURE_NAMES, extract_features  # noqa: E402

ARTIFACTS = ROOT / "models" / "artifacts"


def payload_text(record: dict) -> str:
    """The span the classifier actually scores at serving time.

    L2 scores untrusted spans individually rather than the whole prompt, so
    training on the concatenated conversation would teach it a different
    task than the one it performs.
    """
    for message in reversed(record.get("messages", [])):
        if message.get("role") in {"tool", "function"}:
            return str(message.get("content", ""))
    for message in reversed(record.get("messages", [])):
        if message.get("role") == "user":
            return str(message.get("content", ""))
    return ""


def build_dataset(records: list[dict]) -> tuple[list[list[float]], list[int], list[str]]:
    X: list[list[float]] = []
    y: list[int] = []
    ids: list[str] = []
    for record in records:
        text = payload_text(record)
        if len(text.strip()) < 12:
            continue
        X.append(extract_features(text))
        y.append(int(record.get("label", 0)))
        ids.append(record.get("id", "?"))
    return X, y, ids


def split_by_family(records: list[dict], holdout: float = 0.25, seed: int = 20260826):
    """Group-aware split.

    Templated records share phrasing within a family, so a random split leaks
    near-duplicates across the boundary and reports an accuracy the model does
    not have. Splitting by family is pessimistic and honest: the holdout
    contains attack shapes the model was never trained on, which is the
    situation it faces in production.
    """
    import random

    rng = random.Random(seed)
    families = sorted({r.get("family", "unknown") for r in records if r.get("label") == 1})
    rng.shuffle(families)
    held = set(families[: max(1, int(len(families) * holdout))])

    train, test = [], []
    benign = [r for r in records if r.get("label") == 0]
    rng.shuffle(benign)
    cut = int(len(benign) * (1 - holdout))

    for record in records:
        if record.get("label") == 0:
            continue
        (test if record.get("family") in held else train).append(record)
    train += benign[:cut]
    test += benign[cut:]
    return train, test, sorted(held)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train the L2 classifier.")
    parser.add_argument("--out", default=str(ARTIFACTS / "classifier.pkl"))
    parser.add_argument("--C", type=float, default=1.0, help="inverse regularisation")
    parser.add_argument("--holdout", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=20260826)
    args = parser.parse_args(argv)

    try:
        import numpy as np
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import classification_report, roc_auc_score
    except ImportError:
        print(
            "scikit-learn is required to train. Install with:\n"
            "    pip install 'promptwall[train]'\n\n"
            "The gateway runs without a trained model: L2 falls back to the\n"
            "built-in feature scorer, and says so in its findings.",
            file=sys.stderr,
        )
        return 1

    records = load_corpus()
    if not records:
        print("no corpus found; run: python scripts/seed_datasets.py", file=sys.stderr)
        return 1

    train, test, held_families = split_by_family(records, args.holdout, args.seed)
    X_train, y_train, _ = build_dataset(train)
    X_test, y_test, test_ids = build_dataset(test)

    if not X_train or len(set(y_train)) < 2:
        print("training split lacks both classes; corpus is too small", file=sys.stderr)
        return 1

    print(f"train: {len(X_train)} samples ({sum(y_train)} attack)")
    print(f"test:  {len(X_test)} samples ({sum(y_test)} attack)")
    print(f"held-out families: {', '.join(held_families)}")

    model = LogisticRegression(
        C=args.C,
        max_iter=2000,
        # Corpora are imbalanced and the costs are asymmetric; without this
        # the model optimises accuracy by under-predicting the minority class.
        class_weight="balanced",
        random_state=args.seed,
    )
    model.fit(np.asarray(X_train, dtype=np.float64), np.asarray(y_train))

    print("\nlearned weights (readable on purpose):")
    for name, weight in sorted(
        zip(FEATURE_NAMES, model.coef_[0], strict=True), key=lambda kv: -abs(kv[1])
    ):
        print(f"  {name:24} {weight:+.3f}")
    print(f"  {'(intercept)':24} {model.intercept_[0]:+.3f}")

    if X_test and len(set(y_test)) > 1:
        probabilities = model.predict_proba(np.asarray(X_test, dtype=np.float64))[:, 1]
        print(f"\nheld-out ROC AUC: {roc_auc_score(y_test, probabilities):.4f}")
        print(classification_report(y_test, (probabilities >= 0.5).astype(int), digits=3))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    import pickle

    out.write_bytes(pickle.dumps({"model": model, "features": list(FEATURE_NAMES)}))
    (out.parent / "training_meta.json").write_text(
        json.dumps(
            {
                "features": list(FEATURE_NAMES),
                "train_samples": len(X_train),
                "test_samples": len(X_test),
                "held_out_families": held_families,
                "C": args.C,
                "seed": args.seed,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"\nwrote {out}")
    print("next: python models/export_onnx.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
