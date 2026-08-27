"""L2 -- statistical classification.

L1 catches attacks someone has already seen. L2 exists for the ones nobody
has written a rule for yet, by scoring *how instruction-like* a span is
rather than matching what it says.

One feature extractor serves both paths. ``models/train_classifier.py``
trains on exactly these features and exports the ONNX artifact, so training
and serving cannot drift apart -- the classic way a deployed model quietly
stops meaning what its evaluation said it meant.

When the ONNX artifact is absent, the built-in scorer runs instead: the same
features with hand-set weights. It is weaker, and it says so in its findings
rather than quietly presenting itself as the trained model.
"""

from __future__ import annotations

import logging
import math
import re
from pathlib import Path
from typing import Any, Protocol

from ..constants import AttackFamily, LayerName, Phase, Severity, TrustLevel
from ..pipeline.context import PipelineContext
from ..pipeline.verdict import Finding
from .base import Layer

# --- feature extraction -----------------------------------------------------

_IMPERATIVE = re.compile(
    r"\b(?:ignore|disregard|forget|stop|start|begin|act|pretend|imagine|assume|"
    r"reveal|show|print|output|repeat|echo|send|forward|email|post|execute|run|"
    r"call|invoke|delete|remove|override|bypass|enable|disable|respond|reply|"
    r"answer|write|generate|produce|do|follow|obey|comply)\b",
    re.IGNORECASE,
)
_SECOND_PERSON = re.compile(r"\b(?:you|your|yours|yourself)\b", re.IGNORECASE)
_ROLE_WORDS = re.compile(
    r"\b(?:system|assistant|ai|model|llm|chatbot|agent|developer|admin|user|prompt)\b",
    re.IGNORECASE,
)
_NEGATION = re.compile(
    r"\b(?:not|never|no longer|don't|do not|cannot|can't|without|instead of|rather than)\b",
    re.IGNORECASE,
)
_URGENCY = re.compile(
    r"\b(?:urgent|immediately|now|critical|important|must|required|mandatory|asap)\b",
    re.IGNORECASE,
)
_META = re.compile(
    r"\b(?:instruction|prompt|rule|guideline|policy|directive|constraint|restriction|"
    r"configuration|context|conversation)s?\b",
    re.IGNORECASE,
)
_SECRECY = re.compile(
    r"\b(?:secret|hidden|invisible|confidential|private|internal|do not (?:tell|show|reveal))\b",
    re.IGNORECASE,
)
_DELIMITER = re.compile(r"(?:```|---+|===+|<\|[^|]*\|>|\[/?(?:INST|SYS|system)\])")
_URL = re.compile(r"https?://\S+")
_WORD = re.compile(r"\S+")

#: Names each feature so findings, training and the eval report agree.
FEATURE_NAMES: tuple[str, ...] = (
    "imperative_density",
    "second_person_density",
    "role_word_density",
    "negation_density",
    "urgency_density",
    "meta_density",
    "secrecy_density",
    "delimiter_count",
    "url_count",
    "caps_ratio",
    "punct_ratio",
    "digit_ratio",
    "nonascii_ratio",
    "avg_word_len",
    "line_count",
    "length_log",
    "imperative_start",
    "colon_directive",
    "newline_density",
    "repeat_ratio",
)


def _density(pattern: re.Pattern, text: str, words: int) -> float:
    if words <= 0:
        return 0.0
    return min(1.0, len(pattern.findall(text)) / words * 10.0)


def extract_features(text: str) -> list[float]:
    """Turn text into the fixed-length vector both scorers consume.

    Every value is squashed to roughly 0..1 so an untrained fallback can use
    hand-set weights meaningfully and a trained model does not need feature
    scaling baked into the ONNX graph.
    """
    if not text:
        return [0.0] * len(FEATURE_NAMES)

    words = _WORD.findall(text)
    n_words = len(words) or 1
    n_chars = len(text) or 1
    letters = [c for c in text if c.isalpha()]

    lines = text.splitlines() or [text]
    unique_lines = len({ln.strip() for ln in lines if ln.strip()})

    return [
        _density(_IMPERATIVE, text, n_words),
        _density(_SECOND_PERSON, text, n_words),
        _density(_ROLE_WORDS, text, n_words),
        _density(_NEGATION, text, n_words),
        _density(_URGENCY, text, n_words),
        _density(_META, text, n_words),
        _density(_SECRECY, text, n_words),
        min(1.0, len(_DELIMITER.findall(text)) / 4.0),
        min(1.0, len(_URL.findall(text)) / 3.0),
        (sum(1 for c in letters if c.isupper()) / len(letters)) if letters else 0.0,
        min(1.0, sum(1 for c in text if c in ".,;:!?-_()[]{}") / n_chars * 5.0),
        min(1.0, sum(1 for c in text if c.isdigit()) / n_chars * 5.0),
        min(1.0, sum(1 for c in text if ord(c) > 127) / n_chars * 10.0),
        min(1.0, (sum(len(w) for w in words) / n_words) / 12.0),
        min(1.0, len(lines) / 30.0),
        min(1.0, math.log10(n_chars + 1) / 4.0),
        1.0 if words and _IMPERATIVE.match(words[0]) else 0.0,
        min(1.0, len(re.findall(r"(?m)^\s*\w[\w \t]{0,30}:\s*\S", text)) / 4.0),
        min(1.0, text.count("\n") / n_chars * 40.0),
        1.0 - (unique_lines / len(lines)) if len(lines) > 1 else 0.0,
    ]


# --- scorers ----------------------------------------------------------------


class Scorer(Protocol):
    """Anything that turns a feature vector into a calibrated probability."""

    kind: str

    def score(self, features: list[float]) -> float: ...


#: Hand-set weights for the fallback. Signs are the interesting part: they
#: encode the working hypothesis that injections are *instruction-shaped* --
#: dense imperatives aimed at "you", talking about prompts and rules, often
#: with secrecy or urgency framing. Magnitudes are deliberately modest so the
#: fallback lands in the review band rather than blocking on its own.
FALLBACK_WEIGHTS: dict[str, float] = {
    "imperative_density": 1.35,
    "second_person_density": 0.95,
    "role_word_density": 1.15,
    "negation_density": 0.55,
    "urgency_density": 0.45,
    "meta_density": 1.60,
    "secrecy_density": 1.30,
    "delimiter_count": 0.70,
    "url_count": 0.35,
    "caps_ratio": 0.60,
    "punct_ratio": 0.10,
    "digit_ratio": -0.25,
    "nonascii_ratio": 0.80,
    "avg_word_len": -0.55,
    "line_count": -0.20,
    "length_log": -0.35,
    "imperative_start": 0.85,
    "colon_directive": 0.60,
    "newline_density": -0.15,
    "repeat_ratio": 0.30,
}
FALLBACK_BIAS = -2.55


class FallbackScorer:
    """Logistic model over the shared features, with hand-set weights.

    Honest about what it is. It exists so a deployment with no trained
    artifact still gets a soft signal instead of a silently missing layer,
    and its findings carry ``fallback: true`` so nobody mistakes its output
    for the evaluated model's.
    """

    kind = "fallback"

    def __init__(self) -> None:
        self._weights = [FALLBACK_WEIGHTS[name] for name in FEATURE_NAMES]

    def score(self, features: list[float]) -> float:
        z = FALLBACK_BIAS + sum(w * f for w, f in zip(self._weights, features, strict=True))
        return 1.0 / (1.0 + math.exp(-z))


class OnnxScorer:
    """Wraps a trained ONNX classifier exported by models/export_onnx.py."""

    kind = "onnx"

    def __init__(self, model_path: str | Path) -> None:
        import numpy as np
        import onnxruntime as ort

        self._np = np
        self._session = ort.InferenceSession(
            str(model_path),
            providers=["CPUExecutionProvider"],
            sess_options=self._session_options(ort),
        )
        self._input_name = self._session.get_inputs()[0].name
        self._outputs = [o.name for o in self._session.get_outputs()]

    @staticmethod
    def _session_options(ort):
        opts = ort.SessionOptions()
        # One thread: the gateway is already concurrent per request, and
        # letting ORT spawn its own pool per session oversubscribes the box.
        opts.intra_op_num_threads = 1
        opts.inter_op_num_threads = 1
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        return opts

    def score(self, features: list[float]) -> float:
        vector = self._np.asarray([features], dtype=self._np.float32)
        outputs = self._session.run(None, {self._input_name: vector})

        # skl2onnx emits [label, probabilities]; probabilities may be a
        # list of dicts or an array depending on the converter version.
        for value in reversed(outputs):
            prob = self._extract_probability(value)
            if prob is not None:
                return prob

        # No output matched a shape we recognise. Returning a guess here
        # would be worse than saying so: a silently wrong probability is
        # indistinguishable from a confident one downstream.
        raise ValueError(
            f"ONNX model produced no recognisable probability output "
            f"(got {[getattr(o, 'shape', type(o).__name__) for o in outputs]})"
        )

    def _extract_probability(self, value: Any) -> float | None:
        if isinstance(value, list) and value and isinstance(value[0], dict):
            # skl2onnx emits the positive class under either 1 or "1"
            # depending on converter version. A missing key must NOT default
            # to 0.0: that reads as "definitely benign" and would fail the
            # layer open silently. Return None so the caller tries the next
            # output, and ultimately raises.
            mapping = value[0]
            raw = mapping.get(1, mapping.get("1"))
            return None if raw is None else float(raw)
        arr = self._np.asarray(value)
        if arr.ndim == 2 and arr.shape[1] >= 2:
            return float(arr[0][1])
        if arr.ndim == 1 and arr.size == 1 and 0.0 <= float(arr[0]) <= 1.0:
            return float(arr[0])
        return None


# --- the layer --------------------------------------------------------------


class ClassifierLayer(Layer):
    name = LayerName.L2_CLASSIFIER
    phase = Phase.INPUT
    cost_ms = 8.0

    def __init__(self, settings) -> None:
        super().__init__(settings)
        self.scorer: Scorer = FallbackScorer()

    def setup(self) -> None:
        cfg = self.settings.classifier
        if not cfg.enabled:
            self.disable("classifier disabled by configuration")
            return

        path = Path(cfg.model_path)
        if path.is_file():
            try:
                self.scorer = OnnxScorer(path)
                # Loud on purpose. A trained model that was never evaluated
                # against the built-in scorer can be *worse* than it -- on a
                # small or unrepresentative corpus it learns artifacts, and
                # the failure mode is silent false positives on ordinary
                # traffic. Verify with models/eval_classifier.py.
                logging.getLogger("promptwall.layers").warning(
                    "L2 is using the trained model at %s. Confirm it beats the "
                    "built-in scorer on your own traffic: python "
                    "models/eval_classifier.py --model %s",
                    path,
                    path,
                )
                return
            except Exception as exc:
                if not cfg.allow_fallback:
                    raise
                self._load_error = f"{type(exc).__name__}: {exc}"

        if not cfg.allow_fallback:
            self.disable(f"classifier model not found at {path} and fallback is disabled")
            return
        self.scorer = FallbackScorer()

    def should_run(self, ctx: PipelineContext) -> tuple[bool, str]:
        ok, reason = super().should_run(ctx)
        if not ok:
            return ok, reason
        if not ctx.text.strip():
            return False, "empty input"
        return True, ""

    def run(self, ctx: PipelineContext) -> list[Finding]:
        findings: list[Finding] = []
        thresholds = self.settings.thresholds

        # Score untrusted spans individually. Scoring the whole prompt lets a
        # long benign conversation dilute a short injection into the noise --
        # exactly the shape of a real indirect attack.
        segments = self._segments(ctx)
        for text, trust, source, span in segments:
            if len(text.strip()) < 12:
                continue
            probability = self.scorer.score(extract_features(text))
            if probability < thresholds.review * 0.6:
                continue

            severity = (
                Severity.HIGH
                if probability >= thresholds.block
                else Severity.MEDIUM
                if probability >= thresholds.review
                else Severity.LOW
            )
            # An untrusted span that scores as instruction-like is the actual
            # threat model; the same score on developer text is not.
            weight = probability * (1.0 if trust <= TrustLevel.THIRD_PARTY else 0.35)

            findings.append(
                Finding(
                    layer=self.name,
                    rule_id=f"l2.{self.scorer.kind}",
                    message=f"content scored {probability:.2f} as instruction-like",
                    severity=severity,
                    family=AttackFamily.INDIRECT
                    if trust <= TrustLevel.THIRD_PARTY
                    else AttackFamily.INSTRUCTION_OVERRIDE,
                    start=span[0],
                    end=span[1],
                    orig_start=(
                        ctx.offsets.span_to_original(*span)[0] if ctx.offsets else span[0]
                    ),
                    orig_end=ctx.offsets.span_to_original(*span)[1] if ctx.offsets else span[1],
                    trust=trust,
                    source=source,
                    confidence=probability,
                    weight=min(1.0, weight),
                    meta={
                        "scorer": self.scorer.kind,
                        "fallback": self.scorer.kind == "fallback",
                    },
                )
            )

        ctx.note("l2.scorer", self.scorer.kind)
        return findings

    def _segments(self, ctx: PipelineContext):
        """Untrusted spans if we have provenance, else the whole text."""
        taint = ctx.normalized_taint or ctx.raw_taint
        text = ctx.text
        if taint is None:
            return [(text, TrustLevel.UNTRUSTED, "unlabelled", (0, len(text)))]

        untrusted = taint.regions_at_or_below(TrustLevel.THIRD_PARTY)
        if not untrusted:
            return [(text, taint.lowest_trust, "conversation", (0, len(text)))]
        return [
            (text[s.start : s.end], s.trust, s.source, (s.start, s.end)) for s in untrusted
        ]
