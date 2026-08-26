"""The proxy: provider adapters, upstream client and the guarded endpoints."""

from .providers import PROVIDERS, Provider, get_provider
from .router import router
from .schemas import (
    AnthropicRequest,
    BlockedResponse,
    ChatCompletionRequest,
    ChatMessage,
    ToolCallSpec,
)
from .streaming import SSEParser, StreamGuard
from .upstream import UpstreamClient, close_client, get_client

__all__ = [
    "PROVIDERS",
    "AnthropicRequest",
    "BlockedResponse",
    "ChatCompletionRequest",
    "ChatMessage",
    "Provider",
    "SSEParser",
    "StreamGuard",
    "ToolCallSpec",
    "UpstreamClient",
    "close_client",
    "get_client",
    "get_provider",
    "router",
]
