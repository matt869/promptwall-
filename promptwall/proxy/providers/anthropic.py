"""Anthropic Messages API provider.

Two structural differences from the OpenAI shape matter here:

  the system prompt is a top-level field rather than a message, which removes
  all guesswork about which text is developer-authored -- exactly the
  provenance question the rest of PromptWall is built around

  content is a list of typed blocks, so tool calls and text are siblings
  rather than separate fields, and rewriting text means editing blocks in
  place instead of setting one string
"""

from __future__ import annotations

from typing import Any

from ..schemas import ChatMessage, ToolCallSpec
from .base import Provider


class AnthropicProvider(Provider):
    name = "anthropic"
    chat_path = "/messages"

    def to_messages(self, payload: dict[str, Any]) -> list[ChatMessage]:
        messages: list[ChatMessage] = []
        system = payload.get("system")
        if system:
            messages.append(ChatMessage(role="system", content=_text(system)))

        for raw in payload.get("messages", []):
            content = raw.get("content")
            # A user turn carrying tool_result blocks is not really a user
            # turn: the tool output inside it is untrusted and must not
            # inherit user trust just because of where it was placed.
            if isinstance(content, list) and any(
                isinstance(b, dict) and b.get("type") == "tool_result" for b in content
            ):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "tool_result":
                        messages.append(
                            ChatMessage(
                                role="tool",
                                content=_text(block.get("content")),
                                tool_call_id=str(block.get("tool_use_id", "")),
                            )
                        )
                    else:
                        messages.append(
                            ChatMessage(role=raw.get("role", "user"), content=_text(block))
                        )
                continue
            messages.append(ChatMessage.model_validate(raw))
        return messages

    def system_prompt(self, payload: dict[str, Any]) -> str:
        return _text(payload.get("system"))

    def extract_text(self, response: dict[str, Any]) -> str:
        return "\n".join(
            str(block.get("text", ""))
            for block in response.get("content", []) or []
            if isinstance(block, dict) and block.get("type") == "text"
        )

    def extract_tool_calls(self, response: dict[str, Any]) -> list[ToolCallSpec]:
        calls: list[ToolCallSpec] = []
        for block in response.get("content", []) or []:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                calls.append(
                    ToolCallSpec(
                        id=str(block.get("id", "")),
                        name=str(block.get("name", "")),
                        arguments=block.get("input") or {},
                    )
                )
        return calls

    def replace_text(self, response: dict[str, Any], text: str) -> dict[str, Any]:
        blocks = response.get("content") or []
        replaced = False
        for block in blocks:
            if isinstance(block, dict) and block.get("type") == "text":
                if replaced:
                    block["text"] = ""
                else:
                    block["text"] = text
                    replaced = True
        if not replaced and text:
            blocks.append({"type": "text", "text": text})
            response["content"] = blocks
        return response

    def strip_tool_calls(self, response: dict[str, Any], names: set[str]) -> dict[str, Any]:
        blocks = response.get("content") or []
        kept = [
            b
            for b in blocks
            if not (
                isinstance(b, dict)
                and b.get("type") == "tool_use"
                and str(b.get("name", "")) in names
            )
        ]
        if len(kept) != len(blocks):
            if not any(isinstance(b, dict) and b.get("type") == "text" for b in kept):
                kept.append(
                    {
                        "type": "text",
                        "text": "[PromptWall blocked the tool call this response requested.]",
                    }
                )
            response["content"] = kept
            response["stop_reason"] = "end_turn"
        return response

    def stream_text_delta(self, event: dict[str, Any]) -> str:
        if event.get("type") == "content_block_delta":
            delta = event.get("delta") or {}
            if delta.get("type") == "text_delta":
                return str(delta.get("text", ""))
        return ""

    def rewrite_stream_delta(self, event: dict[str, Any], text: str) -> dict[str, Any]:
        if event.get("type") == "content_block_delta":
            delta = event.get("delta") or {}
            if delta.get("type") == "text_delta":
                delta["text"] = text
        return event


def _text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            item if isinstance(item, str) else str((item or {}).get("text", ""))
            for item in content
        )
    if isinstance(content, dict):
        return str(content.get("text", ""))
    return str(content)
