#!/usr/bin/env python3
"""Compare two benchmark runs and fail on regression.

The CI gate. A security filter degrades quietly: someone loosens a pattern to
fix a false positive, and three attack families stop being caught. Nobody
notices, because the test suite still passes -- unit tests assert on specific
cases, and the ones that broke were never specific cases.

Thresholds are asymmetric on purpose. Recall may not fall at all beyond
noise, because a missed attack is the failure this project exists to prevent.
False positives are allowed to move a little more, because the alternative is
a gate that blocks every legitimate tightening of a rule.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

#: Recall may drop by at most this before the gate fails.
MAX_RECALL_DROP = 0.02
#: False-positive rate may rise by at most this.
MAX_FPR_RISE = 0.03
#: Hard negatives are the deployability signal, so they get a tighter bound.
MAX_HARD_FPR_RISE = 0.02


def load(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def index(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["defence"]: entry for entry in payload.get("results", [])}


def compare(baseline: dict[str, Any], candidate: dict[str, Any], only: str = "") -> int:
    base, cand = index(baseline), index(candidate)
    names = [n for n in cand if n in base and (not only or n == only)]
    if not names:
        print("no comparable defences between the two runs", file=sys.stderr)
        return 2

    failures = 0
    for name in sorted(names):
        b, c = base[name], cand[name]
        recall_delta = c["overall"]["recall"] - b["overall"]["recall"]
        fpr_delta = c["overall"]["fpr"] - b["overall"]["fpr"]
        hard_delta = c.get("hard_negative_fpr", 0) - b.get("hard_negative_fpr", 0)

        print(f"\n{name}")
        print(
            f"  recall        {b['overall']['recall']:.3f} -> "
            f"{c['overall']['recall']:.3f}  ({recall_delta:+.3f})"
        )
        print(
            f"  fpr           {b['overall']['fpr']:.3f} -> "
            f"{c['overall']['fpr']:.3f}  ({fpr_delta:+.3f})"
        )
        print(
            f"  hard-neg fpr  {b.get('hard_negative_fpr', 0):.3f} -> "
            f"{c.get('hard_negative_fpr', 0):.3f}  ({hard_delta:+.3f})"
        )

        if recall_delta < -MAX_RECALL_DROP:
            print(f"  FAIL recall fell more than {MAX_RECALL_DROP}")
            failures += 1
        if fpr_delta > MAX_FPR_RISE:
            print(f"  FAIL false-positive rate rose more than {MAX_FPR_RISE}")
            failures += 1
        if hard_delta > MAX_HARD_FPR_RISE:
            print(f"  FAIL hard-negative FPR rose more than {MAX_HARD_FPR_RISE}")
            failures += 1

        # Newly-missed ids are the actionable part: a maintainer wants the
        # list, not just the aggregate that moved.
        newly_missed = sorted(set(c.get("missed_ids", [])) - set(b.get("missed_ids", [])))
        if newly_missed:
            print(f"  newly missed ({len(newly_missed)}): {', '.join(newly_missed[:12])}")
        newly_caught = sorted(set(b.get("missed_ids", [])) - set(c.get("missed_ids", [])))
        if newly_caught:
            print(f"  newly caught ({len(newly_caught)}): {', '.join(newly_caught[:12])}")

    print()
    if failures:
        print(f"{failures} regression(s) detected", file=sys.stderr)
        return 1
    print("no regressions")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Gate CI on benchmark regressions.")
    parser.add_argument("baseline", help="previous results.json")
    parser.add_argument("candidate", help="new results.json")
    parser.add_argument("--only", default="", help="compare a single defence")
    args = parser.parse_args(argv)

    try:
        return compare(load(args.baseline), load(args.candidate), args.only)
    except FileNotFoundError as exc:
        # A missing baseline is normal on a first run and must not fail CI.
        print(f"baseline not available ({exc}); skipping regression gate")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
