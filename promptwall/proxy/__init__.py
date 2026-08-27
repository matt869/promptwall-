"""The proxy: provider adapters, upstream client and the guarded endpoints."""

from .providers import PROVIDERS, Provider, get_provider

# Aliased: a bare `from .router import router` would rebind the package
# attribute `router` from the MODULE to the APIRouter object, so
# `promptwall.proxy.router` would no longer resolve to the module.
from .router import router as proxy_router
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
    "proxy_router",
]
