"""The null baseline: forward everything.

Present because it is the honest floor. Every other number in the report is
only meaningful relative to what happens with no defence at all, and it makes
the corpus's own class balance visible -- a defence scoring 70% accuracy on a
70%-attack corpus has learned nothing.
"""

from __future__ import annotations

from typing import Any


class NoDefense:
    name = "no_defense"
    available = True
    description = "Forwards every request unchanged."

    def setup(self) -> None:
        return None

    def evaluate(self, record: dict[str, Any]) -> tuple[int, float, str]:
        return 0, 0.0, "allow"

    def teardown(self) -> None:
        return None
