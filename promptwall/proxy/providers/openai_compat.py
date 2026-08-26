"""OpenAI-compatible provider.

Covers OpenAI itself plus the large number of servers that speak the same
Chat Completions shape (vLLM, Together, Groq, Ollama, LM Studio, OpenRouter).
"""

from __future__ import annotations

import json
from typing import Any

from ..schemas import ChatMessage, ToolCallSpec
from .base import Provider


class OpenAICompatProvider(Provider):
    name = "openai_compat"
    chat_path = "/chat/completions"

    def to_messages(self, payload: dict[str, Any]) -> list[ChatMessage]:
        return [ChatMessage.model_validate(m) for m in payload.get("messages", [])]

    def system_prompt(self, payload: dict[str, Any]) -> str:
        parts = [
            _text(m.get("content"))
            for m in payload.get("messages", [])
            if str(m.get("role", "")).lower() in {"system", "developer"}
        ]
        return "\n".join(p for p in parts if p)

    def extract_text(self, response: dict[str, Any]) -> str:
        parts: list[str] = []
        for choice in response.get("choices", []) or []:
            message = choice.get("message") or {}
            content = message.get("content")
            if content:
                parts.append(_text(content))
        return "\n".join(parts)

    def extract_tool_calls(self, response: dict[str, Any]) -> list[ToolCallSpec]:
        calls: list[ToolCallSpec] = []
        for choice in response.get("choices", []) or []:
            message = choice.get("message") or {}
            for call in message.get("tool_calls") or []:
                function = call.get("function") or {}
                calls.append(
                    ToolCallSpec(
                        id=str(call.get("id", "")),
                        name=str(function.get("name", "")),
                        arguments=_parse_args(function.get("arguments")),
                    )
                )
        return calls

    def replace_text(self, response: dict[str, Any], text: str) -> dict[str, Any]:
        choices = response.get("choices") or []
        if not choices:
            return response
        # The guard produces one concatenated string, so it goes back on the
        # first choice; any others are cleared rather than left holding
        # unguarded text.
        for index, choice in enumerate(choices):
            message = choice.setdefault("message", {})
            message["content"] = text if index == 0 else ""
        return response

    def strip_tool_calls(self, response: dict[str, Any], names: set[str]) -> dict[str, Any]:
        for choice in response.get("choices", []) or []:
            message = choice.get("message") or {}
            calls = message.get("tool_calls")
            if not calls:
                continue
            kept = [
                c for c in calls if str((c.get("function") or {}).get("name", "")) not in names
            ]
            if kept:
                message["tool_calls"] = kept
            else:
                message.pop("tool_calls", None)
                choice["finish_reason"] = "stop"
                if not message.get("content"):
                    message["content"] = (
                        "[PromptWall blocked the tool call this response requested.]"
                    )
        return response

    def stream_text_delta(self, event: dict[str, Any]) -> str:
        parts: list[str] = []
        for choice in event.get("choices", []) or []:
            delta = choice.get("delta") or {}
            if delta.get("content"):
                parts.append(str(delta["content"]))
        return "".join(parts)

    def rewrite_stream_delta(self, event: dict[str, Any], text: str) -> dict[str, Any]:
        choices = event.get("choices") or []
        for index, choice in enumerate(choices):
            delta = choice.setdefault("delta", {})
            if "content" in delta:
                delta["content"] = text if index == 0 else ""
        return event


def _parse_args(raw: Any) -> dict[str, Any]:
    """Tool arguments arrive as a JSON *string* in this API."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {"_value": parsed}
        except json.JSONDecodeError:
            # Malformed arguments are still evidence: keep the raw text so
            # L4 can taint-match against it rather than discarding it.
            return {"_raw": raw}
    return {}


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            item if isinstance(item, str) else str((item or {}).get("text", ""))
            for item in content
        )
    return "" if content is None else str(content)
