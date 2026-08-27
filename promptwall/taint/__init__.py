"""Provenance tracking: the backbone of PromptWall's defence."""

from .labels import (
    OffsetMap,
    OffsetMapBuilder,
    OffsetSegment,
    Span,
    TaintMap,
    merge_maps,
)
from .spotlight import (
    SpotlightMode,
    SpotlightResult,
    apply,
    datamark,
    neutralize_sentinels,
    preamble,
)
from .tracker import (
    ROLE_TRUST,
    TrackedMessage,
    flatten,
    label_tool_result,
    summarize,
    track_message,
    track_messages,
    trust_for_role,
    untrusted_spans,
)

__all__ = [
    "ROLE_TRUST",
    "OffsetMap",
    "OffsetMapBuilder",
    "OffsetSegment",
    "Span",
    "SpotlightMode",
    "SpotlightResult",
    "TaintMap",
    "TrackedMessage",
    "apply",
    "datamark",
    "flatten",
    "label_tool_result",
    "merge_maps",
    "neutralize_sentinels",
    "preamble",
    "summarize",
    "track_message",
    "track_messages",
    "trust_for_role",
    "untrusted_spans",
]
