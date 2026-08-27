"""Keyword matching: what most teams build first.

A deliberately representative implementation of the "just add a blocklist"
approach -- a list of phrases people actually reach for, matched
case-insensitively against the whole prompt with no notion of provenance.

It is here to make two failure modes measurable rather than assumed:

  it cannot see an attack that is encoded, spaced out, or spelled with
  homoglyphs, because it never normalizes

  it fires on any text that *discusses* injection, because it has no way to
  tell a security question from an attack -- which is why its hard-negative
  false-positive rate is the interesting column in the report
"""

from __future__ import annotations

import re
from typing import Any

PATTERNS = [
    r"ignore (?:all )?(?:previous|prior|above) instructions?",
    r"disregard (?:the )?(?:above|previous)",
    r"forget everything",
    r"system prompt",
    r"you are now",
    r"developer mode",
    r"\bDAN\b",
    r"jailbreak",
    r"reveal your (?:instructions|prompt)",
    r"repeat everything above",
    r"no restrictions",
    r"prompt injection",
]

_COMPILED = [re.compile(p, re.IGNORECASE) for p in PATTERNS]


class RegexOnly:
    name = "regex_only"
    available = True
    description = "Case-insensitive keyword blocklist over the whole prompt."

    def setup(self) -> None:
        return None

    def evaluate(self, record: dict[str, Any]) -> tuple[int, float, str]:
        text = "\n".join(
            str(m.get("content", "")) for m in record.get("messages", [])
        )
        hits = sum(1 for pattern in _COMPILED if pattern.search(text))
        if hits:
            return 1, min(1.0, 0.5 + 0.15 * hits), "block"
        return 0, 0.0, "allow"

    def teardown(self) -> None:
        return None
