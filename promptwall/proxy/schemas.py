"""Wire formats for the provider APIs we sit in front of.

Deliberately permissive. PromptWall is a proxy, not an API gateway that owns
the schema: rejecting a request because the provider added a field we have
not modelled yet would break callers for no security benefit. So unknown
fields pass through untouched, and validation is limited to the parts we
actually read or rewrite.

The parts we do read are validated strictly, because that is where the
security decisions come from.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..constants import MAX_INPUT_CHARS


class ChatMessage(BaseModel):
    """One message in an OpenAI-style conversation."""

    model_config = ConfigDict(extra="allow")

    role: str = "user"
    #: str, or a list of content parts for multimodal requests.
    content: Any = None
    name: str | None = None
    tool_call_id: str | None = None
    tool_calls: list[dict[str, Any]] | None = None

    #: PromptWall extensions. Applications that know the provenance of a
    #: message should declare it; inference is only a fallback.
    pw_trust: str | int | None = None
    pw_source: str | None = None


class ChatCompletionRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    model: str = "gpt-4o-mini"
    messages: list[ChatMessage] = Field(default_factory=list)
    tools: list[dict[str, Any]] | None = None
    tool_choice: Any = None
    stream: bool = False
    temperature: float | None = None
    max_tokens: int | None = None
    user: str | None = None

    #: Conversation identity for cross-turn analysis. Falls back to the
    #: X-PromptWall-Session header, then to no session at all.
    pw_session_id: str | None = None

    def total_chars(self) -> int:
        return sum(len(_content_str(m.content)) for m in self.messages)

    def oversized(self, limit: int = MAX_INPUT_CHARS) -> bool:
        return self.total_chars() > limit

    def to_upstream(self) -> dict[str, Any]:
        """Serialize for the provider, stripping PromptWall-only fields."""
        payload = self.model_dump(exclude_none=True, exclude={"pw_session_id"})
        for message in payload.get("messages", []):
            message.pop("pw_trust", None)
            message.pop("pw_source", None)
        return payload

    def tool_names(self) -> list[str]:
        names: list[str] = []
        for tool in self.tools or []:
            name = tool.get("name") or tool.get("function", {}).get("name")
            if name:
                names.append(str(name))
        return names


class AnthropicRequest(BaseModel):
    """Anthropic Messages API. The system prompt is a separate field here,
    which is convenient: it removes the guesswork about which text is
    developer-authored."""

    model_config = ConfigDict(extra="allow")

    model: str = "claude-sonnet-5"
    messages: list[ChatMessage] = Field(default_factory=list)
    system: Any = None
    tools: list[dict[str, Any]] | None = None
    stream: bool = False
    max_tokens: int = 1024
    pw_session_id: str | None = None

    def to_chat_messages(self) -> list[ChatMessage]:
        """Normalize onto the internal representation, system message first."""
        out: list[ChatMessage] = []
        if self.system:
            out.append(ChatMessage(role="system", content=_content_str(self.system)))
        out.extend(self.messages)
        return out

    def to_upstream(self) -> dict[str, Any]:
        payload = self.model_dump(exclude_none=True, exclude={"pw_session_id"})
        for message in payload.get("messages", []):
            message.pop("pw_trust", None)
            message.pop("pw_source", None)
        return payload


class ToolCallSpec(BaseModel):
    """A tool call extracted from a provider response, provider-agnostic."""

    model_config = ConfigDict(extra="allow")

    id: str = ""
    name: str = ""
    arguments: dict[str, Any] = Field(default_factory=dict)


class BlockedResponse(BaseModel):
    """What a caller receives when enforcement stops a request."""

    model_config = ConfigDict(extra="forbid")

    error: dict[str, Any]

    @classmethod
    def from_verdict(cls, verdict, message: str = "") -> BlockedResponse:
        return cls(
            error={
                "type": "blocked_by_policy",
                "message": message or "Request blocked by PromptWall policy.",
                "promptwall": verdict.to_client_dict(),
            }
        )


def _content_str(content: Any) -> str:
    """Flatten message content to text for measurement and comparison."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                parts.append(str(item.get("text", "")))
        return "\n".join(parts)
    return str(content)
