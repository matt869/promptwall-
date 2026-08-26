"""Provenance labels: which spans of a string came from where.

This is the load-bearing data structure of the whole system. Every other
layer asks the same question in some form -- "is this text something the
developer wrote, or something the internet handed us?" -- and answers it by
consulting a TaintMap.

See docs/adr/002-taint-over-classification.md for why provenance, rather than
a maliciousness score, is the primary signal.
"""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, field, replace
from typing import Iterable, Iterator

from ..constants import INSTRUCTION_AUTHORITY_FLOOR, TrustLevel


@dataclass(frozen=True, slots=True)
class Span:
    """A half-open range [start, end) carrying a trust level and an origin."""

    start: int
    end: int
    trust: TrustLevel
    #: Human-readable provenance, e.g. "user", "tool:web_fetch", "rag:doc-17".
    source: str = ""
    #: Stable id of the producing message / tool call, for audit correlation.
    origin_id: str = ""

    def __post_init__(self) -> None:
        if self.start < 0 or self.end < self.start:
            raise ValueError(f"invalid span bounds: [{self.start}, {self.end})")

    def __len__(self) -> int:
        return self.end - self.start

    @property
    def empty(self) -> bool:
        return self.end <= self.start

    def overlaps(self, start: int, end: int) -> bool:
        return self.start < end and start < self.end

    def contains(self, index: int) -> bool:
        return self.start <= index < self.end

    def shifted(self, delta: int) -> Span:
        return replace(self, start=self.start + delta, end=self.end + delta)

    def clipped(self, start: int, end: int) -> Span | None:
        """Intersect with [start, end). Returns None when disjoint."""
        lo, hi = max(self.start, start), min(self.end, end)
        if hi <= lo:
            return None
        return replace(self, start=lo, end=hi)

    @property
    def authoritative(self) -> bool:
        """True when instructions inside this span may be honored as commands."""
        return self.trust > INSTRUCTION_AUTHORITY_FLOOR

    def to_dict(self) -> dict[str, object]:
        return {
            "start": self.start,
            "end": self.end,
            "trust": int(self.trust),
            "trust_name": self.trust.name.lower(),
            "source": self.source,
            "origin_id": self.origin_id,
        }


@dataclass(slots=True)
class TaintMap:
    """A total, gap-free partition of ``[0, length)`` into trust-labelled spans.

    Invariants, restored on every mutation:
      * spans are sorted by ``start`` and never overlap
      * together they cover exactly ``[0, length)``
      * adjacent spans with identical labels are merged

    Keeping the map total means ``trust_at`` is defined everywhere and no
    caller has to special-case "unlabelled" text -- unlabelled text is the
    single most dangerous thing in a system like this, so it cannot exist.
    """

    length: int
    spans: list[Span] = field(default_factory=list)
    default_trust: TrustLevel = TrustLevel.UNTRUSTED
    default_source: str = "unlabelled"
    _starts: list[int] = field(default_factory=list, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.length < 0:
            raise ValueError("length must be non-negative")
        self._rebuild()

    # -- construction --------------------------------------------------

    @classmethod
    def uniform(
        cls,
        length: int,
        trust: TrustLevel,
        source: str = "",
        origin_id: str = "",
    ) -> TaintMap:
        """One label covering the whole string. The common case."""
        spans = [Span(0, length, trust, source, origin_id)] if length else []
        return cls(length=length, spans=spans, default_trust=trust, default_source=source)

    # -- invariant maintenance ------------------------------------------

    def _rebuild(self) -> None:
        kept = sorted((s for s in self.spans if not s.empty), key=lambda s: (s.start, s.end))

        # Later spans win on overlap: callers layer more specific labels on top.
        resolved: list[Span] = []
        for span in kept:
            trimmed: list[Span] = []
            for prev in resolved:
                if not prev.overlaps(span.start, span.end):
                    trimmed.append(prev)
                    continue
                left = prev.clipped(prev.start, span.start)
                right = prev.clipped(span.end, prev.end)
                if left:
                    trimmed.append(left)
                if right:
                    trimmed.append(right)
            resolved = sorted(trimmed + [span], key=lambda s: s.start)

        # Fill gaps so the map stays total.
        filled: list[Span] = []
        cursor = 0
        for span in resolved:
            if span.start > cursor:
                filled.append(
                    Span(cursor, span.start, self.default_trust, self.default_source)
                )
            filled.append(span)
            cursor = max(cursor, span.end)
        if cursor < self.length:
            filled.append(Span(cursor, self.length, self.default_trust, self.default_source))

        # Merge identical neighbours to keep the map small.
        merged: list[Span] = []
        for span in filled:
            if (
                merged
                and merged[-1].end == span.start
                and merged[-1].trust == span.trust
                and merged[-1].source == span.source
                and merged[-1].origin_id == span.origin_id
            ):
                merged[-1] = replace(merged[-1], end=span.end)
            else:
                merged.append(span)

        self.spans = merged
        self._starts = [s.start for s in merged]

    # -- queries ---------------------------------------------------------

    def __iter__(self) -> Iterator[Span]:
        return iter(self.spans)

    def __len__(self) -> int:
        return len(self.spans)

    def span_at(self, index: int) -> Span | None:
        if not self.spans or index < 0 or index >= self.length:
            return None
        pos = bisect_right(self._starts, index) - 1
        if pos < 0:
            return None
        span = self.spans[pos]
        return span if span.contains(index) else None

    def trust_at(self, index: int) -> TrustLevel:
        span = self.span_at(index)
        return span.trust if span else self.default_trust

    def overlapping(self, start: int, end: int) -> list[Span]:
        """All spans intersecting [start, end), clipped to that window."""
        if end <= start:
            return []
        out: list[Span] = []
        for span in self.spans:
            if span.start >= end:
                break
            clipped = span.clipped(start, end)
            if clipped:
                out.append(clipped)
        return out

    def min_trust(self, start: int, end: int) -> TrustLevel:
        """Lowest trust anywhere in the window -- the safe way to judge a match.

        A detection straddling a trusted/untrusted boundary is treated as
        untrusted, because an attacker controls where the boundary falls.
        """
        overlaps = self.overlapping(start, end)
        if not overlaps:
            return self.default_trust
        return min(s.trust for s in overlaps)

    def is_authoritative(self, start: int, end: int) -> bool:
        """May text in this window issue instructions?"""
        return self.min_trust(start, end) > INSTRUCTION_AUTHORITY_FLOOR

    def regions_at_or_below(self, floor: TrustLevel) -> list[Span]:
        return [s for s in self.spans if s.trust <= floor]

    @property
    def lowest_trust(self) -> TrustLevel:
        return min((s.trust for s in self.spans), default=self.default_trust)

    def sources(self) -> list[str]:
        seen: dict[str, None] = {}
        for span in self.spans:
            if span.source:
                seen.setdefault(span.source, None)
        return list(seen)

    # -- transformations --------------------------------------------------

    def shifted(self, delta: int, new_length: int | None = None) -> TaintMap:
        return TaintMap(
            length=new_length if new_length is not None else self.length + delta,
            spans=[s.shifted(delta) for s in self.spans],
            default_trust=self.default_trust,
            default_source=self.default_source,
        )

    def slice(self, start: int, end: int) -> TaintMap:
        clipped = [s.clipped(start, end) for s in self.spans]
        return TaintMap(
            length=max(0, end - start),
            spans=[s.shifted(-start) for s in clipped if s is not None],
            default_trust=self.default_trust,
            default_source=self.default_source,
        )

    def with_span(self, span: Span) -> TaintMap:
        """Layer one more label on top. Later labels win on overlap."""
        return TaintMap(
            length=max(self.length, span.end),
            spans=[*self.spans, span],
            default_trust=self.default_trust,
            default_source=self.default_source,
        )

    def project(self, offsets: OffsetMap, new_length: int) -> TaintMap:
        """Carry these labels onto a rewritten string.

        ``offsets`` describes how the new string was built from this one.
        Trust is inherited from the originating characters, so normalization
        can never launder untrusted text into trusted text.
        """
        spans: list[Span] = []
        for seg in offsets.segments:
            for old in self.overlapping(seg.old_start, seg.old_end):
                if seg.old_end > seg.old_start:
                    ratio_lo = (old.start - seg.old_start) / (seg.old_end - seg.old_start)
                    ratio_hi = (old.end - seg.old_start) / (seg.old_end - seg.old_start)
                    width = seg.new_end - seg.new_start
                    lo = seg.new_start + int(ratio_lo * width)
                    hi = seg.new_start + max(1, int(ratio_hi * width)) if width else seg.new_end
                else:
                    lo, hi = seg.new_start, seg.new_end
                lo, hi = max(seg.new_start, lo), min(seg.new_end, max(lo + 1, hi))
                if hi > lo:
                    spans.append(replace(old, start=lo, end=hi))
        return TaintMap(
            length=new_length,
            spans=spans,
            default_trust=self.default_trust,
            default_source=self.default_source,
        )

    def to_list(self) -> list[dict[str, object]]:
        return [s.to_dict() for s in self.spans]


def merge_maps(parts: Iterable[tuple[str, TaintMap]], joiner: str = "") -> tuple[str, TaintMap]:
    """Concatenate labelled fragments, keeping every label aligned.

    The joiner itself is labelled SYSTEM: it is scaffolding we inserted, and
    marking it otherwise would let an attacker's span appear to extend across
    a boundary they do not actually control.
    """
    texts: list[str] = []
    spans: list[Span] = []
    cursor = 0
    for i, (text, tmap) in enumerate(parts):
        if i and joiner:
            spans.append(Span(cursor, cursor + len(joiner), TrustLevel.SYSTEM, "joiner"))
            texts.append(joiner)
            cursor += len(joiner)
        for span in tmap.spans:
            spans.append(span.shifted(cursor))
        texts.append(text)
        cursor += len(text)
    return "".join(texts), TaintMap(length=cursor, spans=spans)


@dataclass(frozen=True, slots=True)
class OffsetSegment:
    """One contiguous piece of a rewrite: [new_start,new_end) came from
    [old_start,old_end) of the source string."""

    new_start: int
    new_end: int
    old_start: int
    old_end: int


@dataclass(slots=True)
class OffsetMap:
    """Bidirectional-ish mapping between a rewritten string and its source.

    L0 normalization folds homoglyphs, strips invisibles and decodes nested
    encodings. Detections then fire against the *normalized* text, but
    redaction and audit have to point at the *original* bytes the caller sent.
    This is what makes that possible.
    """

    segments: list[OffsetSegment] = field(default_factory=list)
    _new_starts: list[int] = field(default_factory=list, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.segments.sort(key=lambda s: s.new_start)
        self._new_starts = [s.new_start for s in self.segments]

    @classmethod
    def identity(cls, length: int) -> OffsetMap:
        return cls(segments=[OffsetSegment(0, length, 0, length)] if length else [])

    def to_original(self, new_index: int) -> int:
        """Best-effort source offset for a position in the rewritten string."""
        if not self.segments:
            return new_index
        pos = bisect_right(self._new_starts, new_index) - 1
        if pos < 0:
            return self.segments[0].old_start
        seg = self.segments[pos]
        if new_index >= seg.new_end:
            return seg.old_end
        new_width = seg.new_end - seg.new_start
        old_width = seg.old_end - seg.old_start
        if new_width <= 0:
            return seg.old_start
        offset = int((new_index - seg.new_start) / new_width * old_width)
        return min(seg.old_end, seg.old_start + offset)

    def span_to_original(self, start: int, end: int) -> tuple[int, int]:
        """Map a half-open range back, widening outward.

        Widening rather than narrowing is deliberate: when a rewrite makes the
        correspondence fuzzy we would rather redact one character too many
        than leak one character of a secret.
        """
        lo = self.to_original(start)
        hi = self.to_original(max(start, end - 1))
        for seg in self.segments:
            if seg.new_start < end and start < seg.new_end:
                lo = min(lo, seg.old_start)
                hi = max(hi, seg.old_end)
        return lo, max(lo, hi)


class OffsetMapBuilder:
    """Accumulates an OffsetMap while a transform emits output."""

    __slots__ = ("_segments", "_new_cursor")

    def __init__(self) -> None:
        self._segments: list[OffsetSegment] = []
        self._new_cursor = 0

    def emit(self, text: str, old_start: int, old_end: int) -> None:
        """Record that ``text`` was produced from source range [old_start, old_end)."""
        if not text:
            return
        seg = OffsetSegment(
            new_start=self._new_cursor,
            new_end=self._new_cursor + len(text),
            old_start=old_start,
            old_end=old_end,
        )
        self._segments.append(seg)
        self._new_cursor += len(text)

    def skip(self, count: int = 1) -> None:
        """Source characters dropped entirely (zero-width, bidi controls...)."""
        _ = count

    @property
    def length(self) -> int:
        return self._new_cursor

    def build(self) -> OffsetMap:
        return OffsetMap(segments=list(self._segments))
