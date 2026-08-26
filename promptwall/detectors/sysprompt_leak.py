"""Detecting when the model is reciting its own instructions.

Exact matching is useless here: a model asked to reveal its prompt will
paraphrase, translate, reformat as a list, or interleave commentary. What
survives all of that is *shared vocabulary in order*, so this uses word-level
shingles rather than string equality.

Containment, not Jaccard. The leak is usually a fragment of a long system
prompt inside a short reply, and Jaccard punishes that length mismatch badly
enough to miss it. Containment asks the right question: how much of the
system prompt turned up in the output?
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_WORD_RE = re.compile(r"[a-z0-9']+")

#: Shingle width. Three words is long enough to be distinctive and short
#: enough to survive light paraphrasing.
SHINGLE_N = 3

#: Fraction of the system prompt's shingles that must appear in the output.
LEAK_THRESHOLD = 0.28
STRONG_LEAK_THRESHOLD = 0.55

#: Phrases that accompany a leak even when the wording is reworked.
_META_RE = re.compile(
    r"(?i)\b(?:"
    r"my (?:system )?(?:prompt|instructions?|guidelines?) (?:are|is|says?)"
    r"|i (?:was|have been) (?:told|instructed|configured|programmed) to"
    r"|here (?:is|are) (?:my|the) (?:system )?(?:prompt|instructions?)"
    r"|the text above (?:says|reads)"
    r"|verbatim(?:ly)? (?:above|preceding)"
    r")\b"
)


@dataclass(slots=True)
class LeakReport:
    containment: float = 0.0
    matched_shingles: int = 0
    total_shingles: int = 0
    meta_phrase: bool = False
    longest_run: int = 0

    @property
    def leaked(self) -> bool:
        # A long verbatim run is conclusive on its own: nobody reproduces
        # twelve consecutive words of a system prompt by coincidence.
        return (
            self.containment >= LEAK_THRESHOLD
            or self.longest_run >= 12
            or (self.meta_phrase and self.containment >= LEAK_THRESHOLD * 0.6)
        )

    @property
    def severity_hint(self) -> str:
        if self.containment >= STRONG_LEAK_THRESHOLD or self.longest_run >= 20:
            return "critical"
        return "high" if self.leaked else "info"


def _words(text: str) -> list[str]:
    return _WORD_RE.findall(text.lower())


def _shingles(words: list[str], n: int = SHINGLE_N) -> set[tuple[str, ...]]:
    if len(words) < n:
        return {tuple(words)} if words else set()
    return {tuple(words[i : i + n]) for i in range(len(words) - n + 1)}


def _longest_common_run(a: list[str], b: list[str], cap: int = 4000) -> int:
    """Longest run of consecutive words shared by both.

    Rolling single row rather than the full DP table: the table would be
    len(a) x len(b), which is unacceptable for a long system prompt plus a
    long reply on the hot path.
    """
    a, b = a[:cap], b[:cap]
    if not a or not b:
        return 0
    previous = [0] * (len(b) + 1)
    best = 0
    for i in range(1, len(a) + 1):
        current = [0] * (len(b) + 1)
        ai = a[i - 1]
        for j in range(1, len(b) + 1):
            if ai == b[j - 1]:
                current[j] = previous[j - 1] + 1
                if current[j] > best:
                    best = current[j]
        previous = current
    return best


def detect_leak(output: str, system_prompt: str, *, n: int = SHINGLE_N) -> LeakReport:
    """How much of ``system_prompt`` shows up in ``output``?"""
    report = LeakReport()
    if not output or not system_prompt:
        return report

    sys_words = _words(system_prompt)
    out_words = _words(output)
    if not sys_words or not out_words:
        return report

    sys_shingles = _shingles(sys_words, n)
    out_shingles = _shingles(out_words, n)
    if not sys_shingles:
        return report

    matched = sys_shingles & out_shingles
    report.total_shingles = len(sys_shingles)
    report.matched_shingles = len(matched)
    report.containment = round(len(matched) / len(sys_shingles), 4)
    report.meta_phrase = bool(_META_RE.search(output))
    # Only pay for the DP when there is already reason to look.
    if report.containment >= LEAK_THRESHOLD * 0.5 or report.meta_phrase:
        report.longest_run = _longest_common_run(sys_words, out_words)
    return report


def leaked(output: str, system_prompt: str) -> bool:
    return detect_leak(output, system_prompt).leaked
