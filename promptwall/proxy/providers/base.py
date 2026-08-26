"""Provider abstraction.

Each provider knows three things PromptWall cannot know generically:

  * how to map its wire format onto our internal message representation
  * how to find tool calls in a response
  * how to rewrite a response after the output guard has changed the text

That last one matters more than it sounds. If L5 redacts a secret, the
redacted text has to go back into the provider's own response shape, or the
caller's SDK will fail to parse what we hand back.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..schemas import ChatMessage, ToolCallSpec


class Provider(ABC):
    """Adapter for one upstream API shape."""

    #: Stable label used in metrics and logs.
    name: str
    #: Path appended to the configured base URL.
    chat_path: str

    @abstractmethod
    def to_messages(self, payload: dict[str, Any]) -> list[ChatMessage]:
        """Extract the conversation from a request payload."""

    @abstractmethod
    def system_prompt(self, payload: dict[str, Any]) -> str:
        """Extract developer-authored instructions, for leak detection."""

    @abstractmethod
    def extract_text(self, response: dict[str, Any]) -> str:
        """The assistant's text output, concatenated."""

    @abstractmethod
    def extract_tool_calls(self, response: dict[str, Any]) -> list[ToolCallSpec]:
        """Tool calls the model requested."""

    @abstractmethod
    def replace_text(self, response: dict[str, Any], text: str) -> dict[str, Any]:
        """Put guarded text back into the response, preserving its shape."""

    @abstractmethod
    def strip_tool_calls(self, response: dict[str, Any], names: set[str]) -> dict[str, Any]:
        """Remove tool calls the gate refused, leaving the rest intact."""

    def stream_text_delta(self, event: dict[str, Any]) -> str:
        """Text carried by one streaming event, or empty."""
        return ""

    def rewrite_stream_delta(self, event: dict[str, Any], text: str) -> dict[str, Any]:
        """Replace the text in a streaming event."""
        return event
