#!/usr/bin/env python3
"""Export the trained classifier to ONNX for serving.

ONNX rather than a pickle in production for three reasons: it loads without
scikit-learn (keeping the runtime image small), it is not arbitrary code
execution on load the way an unpickle is, and onnxruntime's latency is
predictable enough to fit inside the L2 budget.

    python models/export_onnx.py
    PW_L2_MODEL_PATH=models/artifacts/classifier.onnx promptwall serve
"""

from __future__ import annotations

import argparse
import pickle
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from promptwall.layers.l2_classifier import FEATURE_NAMES

ARTIFACTS = ROOT / "models" / "artifacts"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export the L2 classifier to ONNX.")
    parser.add_argument("--model", default=str(ARTIFACTS / "classifier.pkl"))
    parser.add_argument("--out", default=str(ARTIFACTS / "classifier.onnx"))
    parser.add_argument("--opset", type=int, default=15)
    args = parser.parse_args(argv)

    model_path = Path(args.model)
    if not model_path.is_file():
        print(
            f"{model_path} not found. Train first:\n"
            "    python models/train_classifier.py",
            file=sys.stderr,
        )
        return 1

    try:
        import numpy as np
        from skl2onnx import to_onnx
    except ImportError:
        print(
            "skl2onnx is required to export. Install with:\n"
            "    pip install 'promptwall[train]'",
            file=sys.stderr,
        )
        return 1

    bundle = pickle.loads(model_path.read_bytes())
    model, features = bundle["model"], bundle["features"]

    # A model exported with different features than the gateway extracts would
    # produce confident nonsense, so refuse rather than warn.
    if list(features) != list(FEATURE_NAMES):
        print(
            "feature mismatch between the trained model and the serving code:\n"
            f"  trained with : {features}\n"
            f"  serving uses : {list(FEATURE_NAMES)}\n"
            "Retrain against the current extractor.",
            file=sys.stderr,
        )
        return 1

    onnx_model = to_onnx(
        model,
        np.zeros((1, len(FEATURE_NAMES)), dtype=np.float32),
        target_opset=args.opset,
        options={id(model): {"zipmap": False}},
    )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(onnx_model.SerializeToString())
    print(f"wrote {out} ({out.stat().st_size} bytes)")

    # Verify the exported graph agrees with the estimator it came from. An
    # export that silently changes the decision boundary is worse than none.
    try:
        import onnxruntime as ort

        session = ort.InferenceSession(str(out), providers=["CPUExecutionProvider"])
        probe = np.random.RandomState(0).rand(8, len(FEATURE_NAMES)).astype(np.float32)
        expected = model.predict_proba(probe.astype(np.float64))[:, 1]

        outputs = session.run(None, {session.get_inputs()[0].name: probe})
        actual = None
        for value in reversed(outputs):
            array = np.asarray(value)
            if array.ndim == 2 and array.shape[1] >= 2:
                actual = array[:, 1]
                break
        if actual is None:
            print("could not locate probabilities in the ONNX output", file=sys.stderr)
            return 1

        drift = float(np.max(np.abs(expected - actual)))
        print(f"parity check: max probability drift {drift:.2e}")
        if drift > 1e-4:
            print("export does not match the trained model", file=sys.stderr)
            return 1
        print("export verified")
    except ImportError:
        print("onnxruntime not installed; skipping parity check")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
