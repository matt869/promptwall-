"""Shared vocabulary for the whole system.

Everything here is a value type: enums, thresholds, and stable string keys.
No imports from the rest of the package, so this module is safe to import
from anywhere without creating cycles.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum
from typing import Final

PACKAGE_NAME: Final = "promptwall"
API_VERSION: Final = "v1"
AUDIT_SCHEMA_VERSION: Final = 1


class Decision(StrEnum):
    """What the pipeline concluded. Ordered by severity via :data:`DECISION_RANK`."""

    ALLOW = "allow"
    #: Content passes, but spans were rewritten (redaction / spotlighting).
    TRANSFORM = "transform"
    #: Needs a human or a step-up auth check before proceeding.
    CHALLENGE = "challenge"
    BLOCK = "block"


DECISION_RANK: Final[dict[Decision, int]] = {
    Decision.ALLOW: 0,
    Decision.TRANSFORM: 1,
    Decision.CHALLENGE: 2,
    Decision.BLOCK: 3,
}


def escalate(a: Decision, b: Decision) -> Decision:
    """Combine two decisions, taking the more severe. Decisions only ratchet up."""
    return a if DECISION_RANK[a] >= DECISION_RANK[b] else b


class TrustLevel(IntEnum):
    """Provenance of a span of text. Lower is less trusted.

    This is the backbone of the system (see docs/adr/002). Instructions are
    honored based on *where they came from*, not on whether a model thinks
    they look benign.
    """

    #: Fetched from the open internet, or returned by an untrusted tool.
    UNTRUSTED = 0
    #: Retrieved documents, file contents, and other third-party data.
    THIRD_PARTY = 10
    #: Typed by the end user of the application.
    USER = 20
    #: Written by the application developer (system prompt, tool schemas).
    DEVELOPER = 30
    #: PromptWall's own scaffolding.
    SYSTEM = 40


#: At or below this level, embedded instructions never carry authority.
INSTRUCTION_AUTHORITY_FLOOR: Final = TrustLevel.USER


class Phase(StrEnum):
    """Pipeline phases. Layers register themselves against exactly one."""

    INPUT = "input"
    TOOL = "tool"
    OUTPUT = "output"
    SESSION = "session"


class LayerName(StrEnum):
    L0_NORMALIZE = "l0_normalize"
    L1_HEURISTICS = "l1_heuristics"
    L2_CLASSIFIER = "l2_classifier"
    L3_JUDGE = "l3_judge"
    L4_TOOL_GATE = "l4_tool_gate"
    L5_OUTPUT_GUARD = "l5_output_guard"
    L6_CONVERSATION = "l6_conversation"


#: Canonical execution order. The orchestrator will not run them any other way.
LAYER_ORDER: Final[tuple[LayerName, ...]] = (
    LayerName.L0_NORMALIZE,
    LayerName.L1_HEURISTICS,
    LayerName.L2_CLASSIFIER,
    LayerName.L3_JUDGE,
    LayerName.L4_TOOL_GATE,
    LayerName.L5_OUTPUT_GUARD,
    LayerName.L6_CONVERSATION,
)


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK: Final[dict[Severity, int]] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

#: Weight each severity contributes to an aggregate risk score.
SEVERITY_WEIGHT: Final[dict[Severity, float]] = {
    Severity.INFO: 0.0,
    Severity.LOW: 0.10,
    Severity.MEDIUM: 0.30,
    Severity.HIGH: 0.60,
    Severity.CRITICAL: 0.95,
}


class AttackFamily(StrEnum):
    """Taxonomy used by signatures, the benchmark, and the failure analysis."""

    #: "Ignore previous instructions", "you are now DAN", ...
    INSTRUCTION_OVERRIDE = "instruction_override"
    #: Injection arriving through retrieved content rather than the user turn.
    INDIRECT = "indirect"
    #: base64 / rot13 / homoglyph / zero-width smuggling.
    ENCODING = "encoding"
    #: Coaxing the model into calling tools it should not.
    TOOL_ABUSE = "tool_abuse"
    #: Getting data out: markdown image beacons, URLs with payloads.
    EXFILTRATION = "exfiltration"
    #: "Repeat everything above", "print your instructions".
    SYSPROMPT_LEAK = "sysprompt_leak"
    #: Risk that only becomes visible across several turns (crescendo).
    MULTITURN = "multiturn"
    #: Persona / fiction framing used to launder a disallowed request.
    ROLEPLAY = "roleplay"
    #: Benign traffic. Present so datasets and reports share one vocabulary.
    NONE = "none"


class RedactionMode(StrEnum):
    #: Replace with a stable placeholder, e.g. [REDACTED:aws_key].
    MASK = "mask"
    #: Replace with a reversible token so the app can re-hydrate it.
    TOKENIZE = "tokenize"
    #: Keep the last N characters, mask the rest.
    PARTIAL = "partial"
    #: Drop the whole message.
    DROP = "drop"


class Mode(StrEnum):
    """Deployment posture. Always start in MONITOR."""

    MONITOR = "monitor"
    ENFORCE = "enforce"


class FailMode(StrEnum):
    OPEN = "open"
    CLOSED = "closed"


# --- Spotlighting -----------------------------------------------------------
# Delimiters wrapped around untrusted content before it reaches the model, so
# the model can tell data from instructions. Chosen to be unlikely to appear in
# natural text and cheap to tokenize.
SPOTLIGHT_OPEN: Final = "<<<pw:untrusted-data"
SPOTLIGHT_CLOSE: Final = "pw:end-untrusted-data>>>"
#: Character interleaved between words in datamarking mode.
DATAMARK_GLYPH: Final = "▁"  # LOWER ONE EIGHTH BLOCK

# --- Limits -----------------------------------------------------------------
MAX_INPUT_CHARS: Final = 512_000
MAX_DECODE_DEPTH: Final = 3
MAX_DECODE_CANDIDATES: Final = 24
MIN_ENCODED_LEN: Final = 16
MAX_SPOTLIGHT_CHARS: Final = 64_000
DEFAULT_CACHE_SIZE: Final = 4096
DEFAULT_CACHE_TTL_S: Final = 300

# --- Header / field names ---------------------------------------------------
HEADER_REQUEST_ID: Final = "x-promptwall-request-id"
HEADER_DECISION: Final = "x-promptwall-decision"
HEADER_RISK: Final = "x-promptwall-risk"
HEADER_SESSION: Final = "x-promptwall-session"
HEADER_TRACE: Final = "x-promptwall-trace"

#: Applications tell us provenance with this field on a message. Absent means
#: we fall back to role-based inference (see taint.tracker).
FIELD_TRUST: Final = "pw_trust"
FIELD_SOURCE: Final = "pw_source"
