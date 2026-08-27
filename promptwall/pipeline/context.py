"""The mutable state that flows through the layers.

One context per request phase. Layers read what earlier layers produced and
write their own results back, which keeps them independently testable: a
layer is just a function from context to findings.

The context deliberately keeps *both* the original text and every rewritten
form of it. Detections happen in normalized space, but redaction and audit
have to point at what the caller actually sent, and the only way to have both
is to never throw the original away.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..constants import Phase, TrustLevel
from ..detectors.encoding import Decoded
from ..taint.labels import OffsetMap, TaintMap
from ..taint.tracker import TrackedMessage
from .verdict import Verdict

if TYPE_CHECKING:
    from ..config import Settings
    from ..policy.engine import PolicyEngine
    from ..session.store import SessionState


@dataclass(slots=True)
class ToolCall:
    """A tool invocation the model asked for."""

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    call_id: str = ""
    #: Which arguments carry values derived from untrusted spans.
    tainted_args: dict[str, bool] = field(default_factory=dict)
    #: True when untrusted content was in context and appears to have
    #: motivated this call. Set by L4 from the taint map, not guessed.
    request_tainted: bool = False
    #: Trust of the context authorizing the call.
    request_trust: TrustLevel = TrustLevel.USER

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "call_id": self.call_id,
            "tainted_args": sorted(k for k, v in self.tainted_args.items() if v),
            "request_tainted": self.request_tainted,
            "request_trust": self.request_trust.name.lower(),
        }


@dataclass(slots=True)
class PipelineContext:
    """Everything a layer needs, and everywhere it puts what it found."""

    settings: Settings
    engine: PolicyEngine
    phase: Phase = Phase.INPUT
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    session_id: str = ""

    # --- input side ---
    messages: list[TrackedMessage] = field(default_factory=list)
    #: Flattened conversation, exactly as received.
    raw_text: str = ""
    raw_taint: TaintMap | None = None
    #: The developer-authored instructions, kept apart for leak detection.
    system_prompt: str = ""

    # --- L0 products ---
    normalized: str = ""
    normalized_taint: TaintMap | None = None
    #: Maps normalized offsets back to raw offsets.
    offsets: OffsetMap | None = None
    decoded: list[Decoded] = field(default_factory=list)

    # --- tool / output side ---
    tool_calls: list[ToolCall] = field(default_factory=list)
    output_text: str = ""
    output_taint: TaintMap | None = None

    # --- results ---
    verdict: Verdict = field(default_factory=Verdict)
    session: SessionState | None = None
    #: Free-form layer-to-layer channel. Keys are namespaced by layer.
    scratch: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.verdict.request_id = self.request_id
        self.verdict.session_id = self.session_id
        self.verdict.phase = self.phase

    # -- convenience ----------------------------------------------------

    @property
    def text(self) -> str:
        """The best available rendering for scanning: normalized if L0 ran."""
        return self.normalized or self.raw_text

    @property
    def taint(self) -> TaintMap:
        if self.normalized and self.normalized_taint is not None:
            return self.normalized_taint
        if self.raw_taint is not None:
            return self.raw_taint
        return TaintMap.uniform(len(self.raw_text), TrustLevel.UNTRUSTED, "unlabelled")

    @property
    def has_untrusted(self) -> bool:
        """Is any part of this request low-trust? Gates the expensive layers."""
        return self.taint.lowest_trust <= TrustLevel.THIRD_PARTY

    @property
    def lowest_trust(self) -> TrustLevel:
        return self.taint.lowest_trust

    def untrusted_text(self) -> str:
        """Just the untrusted spans, concatenated. What L3 judges."""
        taint = self.taint
        text = self.text
        return "\n---\n".join(
            text[span.start : span.end]
            for span in taint.regions_at_or_below(TrustLevel.THIRD_PARTY)
        )

    def note(self, key: str, value: Any) -> None:
        self.scratch[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self.scratch.get(key, default)

    def to_debug_dict(self) -> dict[str, Any]:
        """Shape for the admin replay view. No raw content."""
        return {
            "request_id": self.request_id,
            "session_id": self.session_id,
            "phase": self.phase.value,
            "messages": len(self.messages),
            "raw_chars": len(self.raw_text),
            "normalized_chars": len(self.normalized),
            "decoded_payloads": len(self.decoded),
            "tool_calls": [call.to_dict() for call in self.tool_calls],
            "lowest_trust": self.lowest_trust.name.lower(),
            "has_untrusted": self.has_untrusted,
            "scratch_keys": sorted(self.scratch),
        }
