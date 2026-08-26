"""Deciding where each piece of a request came from.

The proxy receives a flat list of chat messages. This module turns that into
labelled text: every character gets a TrustLevel and a source string before
any detector looks at it.

Role inference is the fallback. Applications that know better should say so
explicitly with the ``pw_trust`` / ``pw_source`` fields on a message, which
always win over inference.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from ..constants import FIELD_SOURCE, FIELD_TRUST, TrustLevel
from .labels import Span, TaintMap, merge_maps

#: Role -> trust. The two entries that matter:
#:
#: ``tool`` is UNTRUSTED because tool output is the primary indirect-injection
#: vector -- a fetched page, a database row, someone else's calendar invite.
#:
#: ``assistant`` is THIRD_PARTY rather than USER because a prior turn may
#: already carry an injection forward; the model's own history is evidence,
#: not authority.
ROLE_TRUST: dict[str, TrustLevel] = {
    "system": TrustLevel.DEVELOPER,
    "developer": TrustLevel.DEVELOPER,
    "user": TrustLevel.USER,
    "assistant": TrustLevel.THIRD_PARTY,
    "model": TrustLevel.THIRD_PARTY,
    "tool": TrustLevel.UNTRUSTED,
    "function": TrustLevel.UNTRUSTED,
    "ipython": TrustLevel.UNTRUSTED,
}

DEFAULT_TRUST = TrustLevel.UNTRUSTED

_TRUST_BY_NAME = {level.name.lower(): level for level in TrustLevel}


def parse_trust(value: Any) -> TrustLevel | None:
    """Accept a level name, an int, or a TrustLevel. Unknown values -> None."""
    if value is None:
        return None
    if isinstance(value, TrustLevel):
        return value
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        try:
            return TrustLevel(value)
        except ValueError:
            # Clamp to the nearest defined level rather than trusting a
            # number we do not recognise.
            known = sorted(TrustLevel)
            return min(known, key=lambda lvl: abs(int(lvl) - value))
    if isinstance(value, str):
        return _TRUST_BY_NAME.get(value.strip().lower())
    return None


def trust_for_role(role: str) -> TrustLevel:
    return ROLE_TRUST.get((role or "").strip().lower(), DEFAULT_TRUST)


@dataclass(slots=True)
class TrackedMessage:
    """One chat message, flattened to text and labelled."""

    index: int
    role: str
    text: str
    taint: TaintMap
    source: str
    trust: TrustLevel
    #: Tool call id, when this message is a tool result.
    tool_call_id: str = ""
    #: True when the application declared trust rather than us inferring it.
    declared: bool = False
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def authoritative(self) -> bool:
        return self.taint.is_authoritative(0, len(self.text))


def _stringify_part(part: Any) -> str:
    """Flatten one content part of a multimodal message to text."""
    if isinstance(part, str):
        return part
    if not isinstance(part, dict):
        return str(part)
    kind = part.get("type")
    if kind == "text":
        return str(part.get("text", ""))
    if kind in {"image_url", "image"}:
        # We do not OCR images here, but the URL itself is attacker-controlled
        # and has been used to smuggle instructions and to exfiltrate data.
        url = part.get("image_url")
        if isinstance(url, dict):
            url = url.get("url", "")
        return f"[image: {url}]" if url else "[image]"
    if kind == "tool_result":
        return _stringify_content(part.get("content"))
    if kind == "tool_use":
        return json.dumps(part.get("input", {}), ensure_ascii=False, sort_keys=True)
    for key in ("text", "content", "value"):
        if key in part:
            return _stringify_content(part[key])
    return json.dumps(part, ensure_ascii=False, sort_keys=True)


def _stringify_content(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(_stringify_part(p) for p in content)
    return _stringify_part(content)


def track_message(message: dict[str, Any], index: int = 0) -> TrackedMessage:
    """Label a single message."""
    role = str(message.get("role", "user"))
    text = _stringify_content(message.get("content"))

    declared_trust = parse_trust(message.get(FIELD_TRUST))
    trust = declared_trust if declared_trust is not None else trust_for_role(role)

    tool_call_id = str(message.get("tool_call_id") or message.get("tool_use_id") or "")
    declared_source = message.get(FIELD_SOURCE)
    if declared_source:
        source = str(declared_source)
    elif role in {"tool", "function"}:
        name = message.get("name") or tool_call_id or "unknown"
        source = f"tool:{name}"
    else:
        source = role

    taint = TaintMap.uniform(len(text), trust, source, tool_call_id)
    return TrackedMessage(
        index=index,
        role=role,
        text=text,
        taint=taint,
        source=source,
        trust=trust,
        tool_call_id=tool_call_id,
        declared=declared_trust is not None,
        raw=message,
    )


def track_messages(messages: Sequence[dict[str, Any]]) -> list[TrackedMessage]:
    return [track_message(m, i) for i, m in enumerate(messages)]


def flatten(
    tracked: Iterable[TrackedMessage], joiner: str = "\n\n"
) -> tuple[str, TaintMap]:
    """Concatenate tracked messages into one labelled string.

    Used by layers that need to reason over the whole prompt at once (L1, L2,
    L6). Per-message layers should iterate instead and keep the boundaries.
    """
    return merge_maps(((m.text, m.taint) for m in tracked), joiner=joiner)


def label_tool_result(
    name: str,
    content: Any,
    *,
    tool_call_id: str = "",
    trust: TrustLevel = TrustLevel.UNTRUSTED,
) -> tuple[str, TaintMap]:
    """Label the output of a tool the application just executed.

    Call this on the way *back* from a tool so the result is untrusted before
    it is ever appended to the conversation.
    """
    text = _stringify_content(content)
    return text, TaintMap.uniform(len(text), trust, f"tool:{name}", tool_call_id)


def summarize(tracked: Sequence[TrackedMessage]) -> dict[str, Any]:
    """Compact provenance summary for logs and the admin replay view."""
    by_trust: dict[str, int] = {}
    for m in tracked:
        key = m.trust.name.lower()
        by_trust[key] = by_trust.get(key, 0) + len(m.text)
    return {
        "messages": len(tracked),
        "chars_by_trust": by_trust,
        "sources": sorted({m.source for m in tracked if m.source}),
        "untrusted_messages": sum(1 for m in tracked if m.trust <= TrustLevel.THIRD_PARTY),
        "declared_messages": sum(1 for m in tracked if m.declared),
    }


def untrusted_spans(taint: TaintMap, floor: TrustLevel = TrustLevel.THIRD_PARTY) -> list[Span]:
    return taint.regions_at_or_below(floor)
