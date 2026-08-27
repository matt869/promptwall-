"""Running a corpus against one or more defences.

Everything is offline and deterministic by default. A benchmark you cannot
re-run on a laptop, in CI, and get the same numbers from is a benchmark
nobody checks.

The PromptWall adapter runs the real pipeline -- the same code the gateway
executes, not a reimplementation -- because a benchmark that measures a
special "evaluation path" measures the wrong thing.
"""

from __future__ import annotations

import argparse
import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Protocol

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "bench" / "datasets"
RESULTS = ROOT / "bench" / "results"

import sys

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bench.harness.metrics import Outcome, Results


class Defence(Protocol):
    name: str
    available: bool

    def setup(self) -> None: ...
    def evaluate(self, record: dict[str, Any]) -> tuple[int, float, str]: ...
    def teardown(self) -> None: ...


# --- corpus loading --------------------------------------------------------


def iter_records(data_dir: Path = DATA, splits: list[str] | None = None) -> Iterator[dict]:
    """Yield every record from the requested splits, in a stable order."""
    for path in sorted(data_dir.rglob("*.jsonl")):
        relative = path.relative_to(data_dir).as_posix()
        if splits and not any(relative.startswith(s) for s in splits):
            continue
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                record.setdefault("split", relative)
                yield record


def load_corpus(data_dir: Path = DATA, splits: list[str] | None = None) -> list[dict]:
    return list(iter_records(data_dir, splits))


# --- the PromptWall adapter ------------------------------------------------


class PromptWallDefence:
    """Runs the real pipeline, optionally with layers ablated."""

    available = True

    def __init__(self, layers: list[str] | None = None, mode: str = "enforce") -> None:
        self.layers = layers
        self.mode = mode
        self.name = "promptwall" if not layers else "promptwall[" + ",".join(layers) + "]"
        self.description = "Full L0-L6 pipeline" if not layers else f"Ablated: {layers}"
        self._pipeline = None

    def setup(self) -> None:
        from promptwall.config import Settings
        from promptwall.constants import LayerName, Mode
        from promptwall.layers.registry import build_registry
        from promptwall.pipeline.orchestrator import Pipeline
        from promptwall.policy.loader import PolicyStore
        from promptwall.session.store import MemorySessionStore

        settings = Settings(
            mode=Mode(self.mode), auth_required=False, log_level="CRITICAL"
        )
        only = [LayerName(name) for name in self.layers] if self.layers else None
        self._pipeline = Pipeline(
            settings=settings,
            registry=build_registry(settings, only=only),
            policy_store=PolicyStore(),
            session_store=MemorySessionStore(ttl_s=3600),
        )

    def evaluate(self, record: dict[str, Any]) -> tuple[int, float, str]:
        assert self._pipeline is not None
        ctx = self._pipeline.inspect_request(
            record["messages"], session_id=record.get("session_id", "")
        )
        # Multi-turn records carry a session id so L6 can see the trajectory.
        if record.get("session_id"):
            ctx = self._pipeline.close_turn(ctx)

        verdict = ctx.verdict
        # A challenge counts as a detection: it interrupts the attack. The
        # report shows block and challenge separately so this is visible
        # rather than buried in a single number.
        detected = verdict.decision.value in {"block", "challenge"}
        return (1 if detected else 0), verdict.risk, verdict.decision.value

    def teardown(self) -> None:
        if self._pipeline is not None:
            self._pipeline.registry.teardown()
            self._pipeline = None


# --- defence registry ------------------------------------------------------


def build_defences(names: list[str]) -> list[Defence]:
    from bench.baselines.llama_guard import LlamaGuard
    from bench.baselines.no_defense import NoDefense
    from bench.baselines.rebuff import Rebuff
    from bench.baselines.regex_only import RegexOnly

    registry: dict[str, Any] = {
        "no_defense": NoDefense,
        "regex_only": RegexOnly,
        "rebuff": Rebuff,
        "llama_guard": LlamaGuard,
        "promptwall": PromptWallDefence,
    }

    out: list[Defence] = []
    for name in names:
        if name.startswith("promptwall[") and name.endswith("]"):
            layers = [x for x in name[len("promptwall[") : -1].split(",") if x]
            out.append(PromptWallDefence(layers=layers))
            continue
        factory = registry.get(name)
        if factory is None:
            raise SystemExit(f"unknown defence {name!r}; known: {sorted(registry)}")
        out.append(factory())
    return out


ABLATIONS = {
    "l0_only": ["l0_normalize"],
    "no_l0": ["l1_heuristics", "l2_classifier", "l4_tool_gate"],
    "l1_only": ["l0_normalize", "l1_heuristics"],
    "l2_only": ["l0_normalize", "l2_classifier"],
    "no_l2": ["l0_normalize", "l1_heuristics", "l4_tool_gate"],
}


# --- execution -------------------------------------------------------------


def run_defence(defence: Defence, corpus: list[dict], *, warmup: int = 5) -> Results:
    results = Results(defence=defence.name)
    defence.setup()
    try:
        # Warm the compiled-pattern and model caches, or the first few
        # records absorb one-off costs and skew the latency percentiles.
        for record in corpus[:warmup]:
            try:
                defence.evaluate(record)
            except Exception:
                break

        for record in corpus:
            started = time.perf_counter()
            try:
                predicted, risk, decision = defence.evaluate(record)
                error = ""
            except Exception as exc:
                predicted, risk, decision = 0, 0.0, "error"
                error = f"{type(exc).__name__}: {exc}"
            elapsed = (time.perf_counter() - started) * 1000.0

            # Context-only records (intermediate crescendo turns) are run so
            # the defence can build session state, then dropped before scoring.
            if not record.get("score", True):
                continue

            results.add(
                Outcome(
                    record_id=record.get("id", "?"),
                    family=record.get("family", "unknown"),
                    label=int(record.get("label", 0)),
                    predicted=predicted,
                    risk=risk,
                    latency_ms=elapsed,
                    decision=decision,
                    tags=list(record.get("tags", [])),
                    error=error,
                )
            )
    finally:
        defence.teardown()
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the PromptWall benchmark.")
    parser.add_argument(
        "--defences",
        default="no_defense,regex_only,rebuff,promptwall",
        help="comma-separated; use promptwall[l0_normalize,l1_heuristics] to ablate",
    )
    parser.add_argument("--splits", default="", help="comma-separated split prefixes")
    parser.add_argument("--data", default=str(DATA))
    parser.add_argument("--out", default="", help="write JSON results here")
    parser.add_argument("--ablations", action="store_true", help="also run the standard ablations")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    corpus = load_corpus(Path(args.data), [s for s in args.splits.split(",") if s])
    if not corpus:
        raise SystemExit(
            f"no records under {args.data}. Run: python scripts/seed_datasets.py"
        )

    names = [n for n in args.defences.split(",") if n]
    defences = build_defences(names)
    if args.ablations:
        defences.extend(PromptWallDefence(layers=layers) for layers in ABLATIONS.values())

    attacks = sum(r["label"] for r in corpus)
    if not args.quiet:
        print(f"corpus: {len(corpus)} records ({attacks} attack, {len(corpus) - attacks} benign)")

    all_results: list[Results] = []
    for defence in defences:
        if not getattr(defence, "available", True):
            reason = getattr(defence, "unavailable_reason", "not configured")
            if not args.quiet:
                print(f"  {defence.name:28} SKIPPED ({reason})")
            continue
        results = run_defence(defence, corpus)
        all_results.append(results)
        if not args.quiet:
            matrix = results.overall
            print(
                f"  {defence.name:28} recall={matrix.recall:.3f} "
                f"fpr={matrix.fpr:.3f} hard-neg-fpr={results.hard_negative_fpr:.3f} "
                f"p99={results.latency_summary().get('p99_ms', 0):.2f}ms"
            )

    if args.out:
        payload = {
            "corpus": {"records": len(corpus), "attacks": attacks},
            "results": [r.to_dict() for r in all_results],
        }
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        if not args.quiet:
            print(f"\nwrote {out_path}")

    globals()["LAST_RESULTS"] = all_results
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
