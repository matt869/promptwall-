"""Encoding tricks: invisible characters, confusables and nested payloads.

Two jobs, both feeding L0:

  *Unmasking*  strip what humans cannot see and fold what only looks like
               ASCII, so a signature written in plain English still matches.
  *Unwrapping* find and decode base64/hex/rot13/URL/HTML-entity payloads, so
               the same signatures get a look at what the model would see
               after it decodes the thing itself.

Decoding is bounded on purpose. Recursion is capped, candidates are capped,
and only plausible text is kept, because an attacker who can make us decode
forever has a denial of service even if they never land an injection.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import contextlib
import html
import math
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field

from ..constants import MAX_DECODE_CANDIDATES, MAX_DECODE_DEPTH, MIN_ENCODED_LEN

#: Characters with no visual rendering that still reach the tokenizer.
#: Zero-width, bidi overrides, word joiners, the Unicode Tag block (which has
#: been used to hide entire instruction sets inside an innocuous sentence),
#: variation selectors and the byte-order mark.
INVISIBLE_RE = re.compile(
    "["
    "​-‏"      # zero-width space/joiners, LRM/RLM
    "‪-‮"      # bidi embedding/override
    "⁠-⁤"      # word joiner, invisible operators
    "⁦-⁩"      # bidi isolates
    "︀-️"      # variation selectors
    "﻿"             # BOM / zero-width no-break space
    "­"             # soft hyphen
    "\U000e0000-\U000e007f"  # Unicode Tag block
    "\U000e0100-\U000e01ef"  # variation selectors supplement
    "]"
)

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WS_RE = re.compile(r"[^\S\n]{3,}")
_BLANKLINE_RE = re.compile(r"\n{4,}")

#: Confusables NFKC does not fold, because they are genuinely distinct
#: characters that merely *look* Latin. This is the "раypal" problem.
CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ј": "j", "һ": "h",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "У": "Y", "Х": "X",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k",
    "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u",
    "χ": "x", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z",
    "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # Fullwidth / mathematical / misc
    "⁄": "/", "∕": "/", "−": "-", "‐": "-", "‑": "-",
    "‒": "-", "–": "-", "—": "-", "‘": "'", "’": "'",
    "‚": "'", "“": '"', "”": '"', "„": '"', "…": "...",
    " ": " ", " ": " ", " ": " ", "　": " ",
}

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")
_B64URL_RE = re.compile(r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{24,})(?![A-Za-z0-9_-])")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-fx])((?:[0-9A-Fa-f]{2}){8,})(?![0-9A-Fa-f])")
_PCT_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
_ENTITY_RE = re.compile(r"(?:&(?:#x?[0-9A-Fa-f]{2,6}|[a-zA-Z]{2,10});){3,}")


@dataclass(slots=True)
class Decoded:
    """One successfully decoded payload."""

    scheme: str
    text: str
    start: int
    end: int
    depth: int = 1
    #: Shannon entropy of the source blob, kept for triage.
    entropy: float = 0.0


@dataclass(slots=True)
class NormalizeReport:
    invisible_removed: int = 0
    confusables_folded: int = 0
    controls_removed: int = 0
    nfkc_changed: bool = False
    decoded: list[Decoded] = field(default_factory=list)

    @property
    def suspicious(self) -> bool:
        return bool(self.invisible_removed or self.confusables_folded or self.decoded)


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts: dict[str, int] = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def looks_like_text(value: str, *, min_printable: float = 0.85) -> bool:
    """Is a decoded blob plausibly human-readable text?

    The gate that keeps decoding useful. Without it every JPEG, UUID and hash
    in a document decodes to mojibake and floods the scanner with noise.
    """
    if len(value) < 4:
        return False
    printable = sum(1 for ch in value if ch.isprintable() or ch in "\n\r\t")
    if printable / len(value) < min_printable:
        return False
    letters = sum(1 for ch in value if ch.isalpha() or ch.isspace())
    return letters / len(value) >= 0.5


def strip_invisible(text: str) -> tuple[str, int]:
    """Remove characters that reach the model but never reach a human."""
    cleaned, count = INVISIBLE_RE.subn("", text)
    cleaned, ctrl = _CONTROL_RE.subn("", cleaned)
    return cleaned, count + ctrl


def fold_confusables(text: str) -> tuple[str, int]:
    """Map lookalike characters onto their ASCII equivalents."""
    if text.isascii():
        return text, 0
    out: list[str] = []
    folded = 0
    for ch in text:
        replacement = CONFUSABLES.get(ch)
        if replacement is not None:
            out.append(replacement)
            folded += 1
        else:
            out.append(ch)
    return "".join(out), folded


def normalize_text(text: str) -> tuple[str, NormalizeReport]:
    """Full normalization pass: NFKC, invisibles, confusables, whitespace.

    Order matters. NFKC first (it folds fullwidth and compatibility forms),
    then invisibles (NFKC leaves them alone), then confusables (which NFKC
    deliberately does not touch), then whitespace collapsing so that
    ``i g n o r e`` style spacing attacks cannot pad a signature apart.
    """
    report = NormalizeReport()

    nfkc = unicodedata.normalize("NFKC", text)
    report.nfkc_changed = nfkc != text

    stripped, removed = strip_invisible(nfkc)
    report.invisible_removed = removed

    folded, folds = fold_confusables(stripped)
    report.confusables_folded = folds

    collapsed = _WS_RE.sub(" ", folded)
    collapsed = _BLANKLINE_RE.sub("\n\n", collapsed)
    return collapsed, report


def _try_base64(blob: str, *, urlsafe: bool = False) -> str | None:
    # urlsafe_b64decode has no validate= parameter, so translate the alphabet
    # and validate through the standard decoder instead. Without validation a
    # non-base64 string decodes to garbage rather than failing, which floods
    # the scanner with junk candidates.
    if urlsafe:
        blob = blob.replace("-", "+").replace("_", "/")
    padded = blob + "=" * (-len(blob) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _try_hex(blob: str) -> str | None:
    try:
        return bytes.fromhex(blob).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def _try_rot13(blob: str) -> str | None:
    try:
        return codecs.decode(blob, "rot_13")
    except (UnicodeError, LookupError):
        return None


#: rot13 is only worth reporting when the *decoded* form reads like English
#: and the source does not; otherwise every ordinary sentence "decodes".
_ENGLISH_HINTS = re.compile(
    r"\b(?:the|and|you|are|ignore|instruction|system|prompt|password|send|email|please)\b",
    re.IGNORECASE,
)


def decode_layer(text: str, depth: int) -> list[Decoded]:
    """One pass of candidate extraction and decoding."""
    found: list[Decoded] = []

    def _add(scheme: str, decoded: str | None, start: int, end: int, source: str) -> None:
        if decoded and looks_like_text(decoded):
            found.append(
                Decoded(
                    scheme=scheme,
                    text=decoded,
                    start=start,
                    end=end,
                    depth=depth,
                    entropy=round(shannon_entropy(source), 3),
                )
            )

    for match in _B64_RE.finditer(text):
        blob = match.group(1)
        if len(blob) >= MIN_ENCODED_LEN:
            _add("base64", _try_base64(blob), *match.span(1), blob)

    for match in _B64URL_RE.finditer(text):
        blob = match.group(1)
        if ("-" in blob or "_" in blob) and len(blob) >= MIN_ENCODED_LEN:
            _add("base64url", _try_base64(blob, urlsafe=True), *match.span(1), blob)

    for match in _HEX_RE.finditer(text):
        blob = match.group(1)
        _add("hex", _try_hex(blob), *match.span(1), blob)

    for match in _PCT_RE.finditer(text):
        blob = match.group(0)
        with contextlib.suppress(UnicodeDecodeError, ValueError):
            _add("percent", urllib.parse.unquote(blob, errors="strict"), *match.span(), blob)

    for match in _ENTITY_RE.finditer(text):
        blob = match.group(0)
        _add("html_entity", html.unescape(blob), *match.span(), blob)

    # rot13 applies to the whole text, not a delimited blob, so it needs the
    # stricter "decoded reads like English, source does not" test.
    if len(text) >= MIN_ENCODED_LEN and not _ENGLISH_HINTS.search(text):
        candidate = _try_rot13(text)
        if candidate and _ENGLISH_HINTS.search(candidate):
            found.append(
                Decoded("rot13", candidate, 0, len(text), depth, round(shannon_entropy(text), 3))
            )

    return found


def decode_all(text: str, max_depth: int = MAX_DECODE_DEPTH) -> list[Decoded]:
    """Recursively decode nested payloads, breadth-first and bounded.

    Layered encodings are common (base64 of a URL-encoded instruction), so a
    single pass is not enough. The caps are the point: recursion depth,
    candidate count and per-item length are all bounded so that a crafted
    input cannot turn the scanner into a decompression bomb.
    """
    results: list[Decoded] = []
    frontier = [text]
    seen: set[str] = {text}

    for depth in range(1, max_depth + 1):
        next_frontier: list[str] = []
        for chunk in frontier:
            for decoded in decode_layer(chunk, depth):
                if decoded.text in seen:
                    continue
                seen.add(decoded.text)
                results.append(decoded)
                next_frontier.append(decoded.text)
                if len(results) >= MAX_DECODE_CANDIDATES:
                    return results
        if not next_frontier:
            break
        frontier = next_frontier
    return results
